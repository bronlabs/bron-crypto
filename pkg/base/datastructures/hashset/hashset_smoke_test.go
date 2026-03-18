package hashset_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

var (
	_ ds.MutableSet[string]           = (*hashset.MutableComparableSet[string])(nil)
	_ ds.MutableSet[*HashableElement] = (*hashset.MutableHashableSet[*HashableElement])(nil)

	_ ds.Set[string]           = (*hashset.ImmutableSet[string])(nil)
	_ ds.Set[*HashableElement] = (*hashset.ImmutableSet[*HashableElement])(nil)

	_ ds.ConcurrentSet[any] = (*hashset.ConcurrentSet[any])(nil)
)

func TestConcurrentSet_Compute_ReplacesElement(t *testing.T) {
	t.Parallel()

	inner := hashset.NewComparable("a", "b", "c")
	cs := hashset.NewConcurrentSet[string](inner)

	// Replace "a" with "d"
	cs.Compute("a", func(e string, exists bool) (string, bool) {
		require.True(t, exists)
		return "d", true
	})

	require.False(t, cs.Contains("a"), "old element 'a' should be removed")
	require.True(t, cs.Contains("d"), "new element 'd' should be present")
	require.Equal(t, 3, cs.Size(), "size should remain 3")
}

func TestConcurrentSet_ComputeIfPresent_ReplacesElement(t *testing.T) {
	t.Parallel()

	inner := hashset.NewComparable("a", "b")
	cs := hashset.NewConcurrentSet[string](inner)

	// Replace "a" with "z"
	cs.ComputeIfPresent("a", func(e string) (string, bool) {
		return "z", true
	})

	require.False(t, cs.Contains("a"), "old element 'a' should be removed")
	require.True(t, cs.Contains("z"), "new element 'z' should be present")
	require.Equal(t, 2, cs.Size(), "size should remain 2")
}

func TestConcurrentSet_ComputeIfPresent_RemovesElement(t *testing.T) {
	t.Parallel()

	inner := hashset.NewComparable("a", "b")
	cs := hashset.NewConcurrentSet[string](inner)

	// Remove "a" by returning shouldStore=false
	cs.ComputeIfPresent("a", func(e string) (string, bool) {
		return "", false
	})

	require.False(t, cs.Contains("a"), "element 'a' should be removed")
	require.Equal(t, 1, cs.Size(), "size should be 1")
}
