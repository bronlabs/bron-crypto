package hashset

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type Value struct {
	value string
}

func (k Value) Hash() [32]byte {
	return sha3.Sum256([]byte(k.value))
}

func TestGet(t *testing.T) {
	obj, err := NewHashSet[Value]([]Value{
		{value: "1"},
		{value: "2"},
	})
	require.NoError(t, err)
	actual, found := obj.Get(Value{value: "1"})
	require.True(t, found)
	require.Equal(t, Value{value: "1"}, actual)
	_, found = obj.Get(Value{value: "3"})
	require.False(t, found)
}

func TestIsEmpty(t *testing.T) {
	obj, err := NewHashSet[Value]([]Value{})
	require.NoError(t, err)
	empty := obj.IsEmpty()
	require.True(t, empty)
	added := obj.Add(Value{value: "1"})
	require.True(t, added)
	empty = obj.IsEmpty()
	require.False(t, empty)
}

func TestContains(t *testing.T) {
	obj, err := NewHashSet[Value]([]Value{
		{value: "1"},
	})
	require.NoError(t, err)
	actual := obj.Contains(Value{value: "1"})
	require.True(t, actual)
	actual = obj.Contains(Value{value: "2"})
	require.False(t, actual)
}

func TestAdd(t *testing.T) {
	obj, err := NewHashSet[Value]([]Value{
		{value: "1"},
	})
	require.NoError(t, err)
	added := obj.Add(Value{value: "2"})
	require.True(t, added)
	require.Equal(t, 2, obj.Size())
	added = obj.Add(Value{value: "2"})
	require.Equal(t, 2, obj.Size())
	require.False(t, added)
}

func TestRemove(t *testing.T) {
	obj, _ := NewHashSet[Value]([]Value{
		{value: "1"},
	})
	obj.Add(Value{value: "1"})
	obj.Add(Value{value: "2"})
	removed := obj.Remove(Value{value: "2"})
	require.True(t, removed)
	_, found := obj.Get(Value{value: "2"})
	require.False(t, found)
	removed = obj.Remove(Value{value: "2"})
	require.False(t, removed)
}

func TestClear(t *testing.T) {
	obj, _ := NewHashSet[Value]([]Value{
		{value: "1"},
	})
	obj.Add(Value{value: "1"})
	obj.Add(Value{value: "2"})
	obj.Clear()
	require.Equal(t, 0, obj.Size())
}

func TestJoin(t *testing.T) {
	set1, _ := NewHashSet[Value]([]Value{})
	set2, _ := NewHashSet[Value]([]Value{})
	set1.Add(Value{value: "1"})
	set1.Add(Value{value: "2"})
	set1.Add(Value{value: "3"})
	set2.Add(Value{value: "4"})
	set2.Add(Value{value: "5"})
	set2.Add(Value{value: "3"})
	newSet := set1.Union(set2)
	require.Equal(t, 5, newSet.Size())
	_, found := newSet.Get(Value{value: "1"})
	require.True(t, found)
	_, found = newSet.Get(Value{value: "2"})
	require.True(t, found)
	_, found = newSet.Get(Value{value: "3"})
	require.True(t, found)
	_, found = newSet.Get(Value{value: "4"})
	require.True(t, found)
	_, found = newSet.Get(Value{value: "5"})
	require.True(t, found)
}

func TestIntersect(t *testing.T) {
	set1, _ := NewHashSet[Value]([]Value{})
	set2, _ := NewHashSet[Value]([]Value{})
	set1.Add(Value{value: "1"})
	set1.Add(Value{value: "2"})
	set1.Add(Value{value: "3"})
	set2.Add(Value{value: "4"})
	set2.Add(Value{value: "5"})
	set2.Add(Value{value: "3"})
	newSet := set1.Intersection(set2)
	require.Equal(t, 1, newSet.Size())
	_, found := newSet.Get(Value{value: "3"})
	require.True(t, found)
}

func TestDisjoint(t *testing.T) {
	set1, _ := NewHashSet[Value]([]Value{})
	set2, _ := NewHashSet[Value]([]Value{})
	set1.Add(Value{value: "1"})
	set1.Add(Value{value: "2"})
	set1.Add(Value{value: "3"})
	set2.Add(Value{value: "4"})
	set2.Add(Value{value: "5"})
	set2.Add(Value{value: "3"})
	newSet := set1.Difference(set2)
	require.Equal(t, 2, newSet.Size())
	_, found := newSet.Get(Value{value: "1"})
	require.True(t, found)
	_, found = newSet.Get(Value{value: "2"})
	require.True(t, found)
}
