package bimap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bimap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

var (
	_ ds.BiMap[string, int]        = (*bimap.ImmutableBiMap[string, int])(nil)
	_ ds.MutableBiMap[string, int] = (*bimap.MutableBiMap[string, int])(nil)
	_ ds.ConcurrentBiMap[any, any] = (*bimap.ConcurrentBiMap[any, any])(nil)
)

func newMutableBiMap(entries ...struct{ k, v string }) ds.MutableBiMap[string, string] {
	m, _ := bimap.NewMutableBiMap[string, string](
		hashmap.NewComparable[string, string](),
		hashmap.NewComparable[string, string](),
	)
	for _, e := range entries {
		m.Put(e.k, e.v)
	}
	return m
}

func TestMutableBiMap_Filter_ReverseMapConsistency(t *testing.T) {
	t.Parallel()

	m := newMutableBiMap(
		struct{ k, v string }{"a", "x"},
		struct{ k, v string }{"b", "y"},
		struct{ k, v string }{"c", "z"},
	)

	filtered := m.Filter(func(key string) bool { return key == "a" || key == "c" })

	require.Equal(t, 2, filtered.Size())
	// Check forward map
	v, ok := filtered.Get("a")
	require.True(t, ok)
	require.Equal(t, "x", v)
	v, ok = filtered.Get("c")
	require.True(t, ok)
	require.Equal(t, "z", v)
	_, ok = filtered.Get("b")
	require.False(t, ok)

	// Check reverse map via Reverse()
	rev := filtered.Reverse()
	require.Equal(t, 2, rev.Size(), "reverse map should have same size as forward")
	rk, ok := rev.Get("x")
	require.True(t, ok)
	require.Equal(t, "a", rk)
	rk, ok = rev.Get("z")
	require.True(t, ok)
	require.Equal(t, "c", rk)
	_, ok = rev.Get("y")
	require.False(t, ok, "value 'y' should not be in filtered reverse map")
}

func TestImmutableBiMap_Filter_ReverseMapConsistency(t *testing.T) {
	t.Parallel()

	m := newMutableBiMap(
		struct{ k, v string }{"a", "x"},
		struct{ k, v string }{"b", "y"},
		struct{ k, v string }{"c", "z"},
	)
	immutable := m.Freeze()

	filtered := immutable.Filter(func(key string) bool { return key == "b" })

	require.Equal(t, 1, filtered.Size())
	v, ok := filtered.Get("b")
	require.True(t, ok)
	require.Equal(t, "y", v)

	rev := filtered.Reverse()
	require.Equal(t, 1, rev.Size(), "reverse map should match forward map size")
	rk, ok := rev.Get("y")
	require.True(t, ok)
	require.Equal(t, "b", rk)
}

func TestMutableBiMap_TryPut_ValueCollision(t *testing.T) {
	t.Parallel()

	m := newMutableBiMap(
		struct{ k, v string }{"a", "x"},
		struct{ k, v string }{"b", "y"},
	)

	// Put (a, y) — value y already maps to key b, should evict b
	m.Put("a", "y")

	require.Equal(t, 1, m.Size(), "b should have been evicted")
	v, ok := m.Get("a")
	require.True(t, ok)
	require.Equal(t, "y", v)
	_, ok = m.Get("b")
	require.False(t, ok, "b should have been evicted when its value was reassigned to a")

	// Check reverse map integrity
	rev := m.Reverse()
	require.Equal(t, 1, rev.Size())
	rk, ok := rev.Get("y")
	require.True(t, ok)
	require.Equal(t, "a", rk)
	_, ok = rev.Get("x")
	require.False(t, ok, "old value x should no longer exist in reverse map")
}
