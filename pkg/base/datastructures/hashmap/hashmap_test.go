package hashmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
)

type data struct {
	value uint64
}

func (d *data) HashCode() uint64 {
	return d.value % 10
}

func (d *data) Equal(rhs *data) bool {
	return d.value == rhs.value
}

var _ ds.Hashable[*data] = (*data)(nil)

func Test_HashableHashMap(t *testing.T) {
	hashMap := hashmap.NewHashableHashMap[*data, int]()

	// check empty map
	require.Zero(t, hashMap.Size())
	require.True(t, hashMap.IsEmpty())
	_, ok := hashMap.Get(&data{value: 348957})
	require.False(t, ok)
	ok = hashMap.ContainsKey(&data{value: 23465123})
	require.False(t, ok)

	// add two non-conflicting
	replaced, _ := hashMap.TryPut(&data{value: 1}, 1)
	require.False(t, replaced)
	replaced, _ = hashMap.TryPut(&data{value: 2}, 2)
	require.False(t, replaced)
	require.Equal(t, 2, hashMap.Size())

	// add two conflicting
	replaced, _ = hashMap.TryPut(&data{value: 3}, 3)
	require.False(t, replaced)
	replaced, _ = hashMap.TryPut(&data{value: 33}, 33)
	require.False(t, replaced)
	require.Equal(t, 4, hashMap.Size())

	// check exists
	require.True(t, hashMap.ContainsKey(&data{value: 1}))
	require.True(t, hashMap.ContainsKey(&data{value: 2}))
	require.True(t, hashMap.ContainsKey(&data{value: 3}))
	require.True(t, hashMap.ContainsKey(&data{value: 33}))
	require.False(t, hashMap.ContainsKey(&data{value: 43}))

	// check gets
	v1, ok := hashMap.Get(&data{value: 1})
	require.True(t, ok)
	require.Equal(t, 1, v1)
	v2, ok := hashMap.Get(&data{value: 2})
	require.True(t, ok)
	require.Equal(t, 2, v2)
	v3, ok := hashMap.Get(&data{value: 3})
	require.True(t, ok)
	require.Equal(t, 3, v3)
	v33, ok := hashMap.Get(&data{value: 33})
	require.True(t, ok)
	require.Equal(t, 33, v33)

	// check remove conflicting
	ok, removed := hashMap.TryRemove(&data{value: 3})
	require.True(t, ok)
	require.Equal(t, 3, removed)
	require.Equal(t, 3, hashMap.Size())
	require.False(t, hashMap.ContainsKey(&data{value: 3}))
	require.True(t, hashMap.ContainsKey(&data{value: 33}))
	_, ok = hashMap.Get(&data{value: 3})
	require.False(t, ok)

	// remove again
	ok, _ = hashMap.TryRemove(&data{value: 3})
	require.False(t, ok)

	// remove non-conflicting
	ok, removed2 := hashMap.TryRemove(&data{value: 2})
	require.True(t, ok)
	require.Equal(t, 2, removed2)
	require.Equal(t, 2, hashMap.Size())
	require.False(t, hashMap.ContainsKey(&data{value: 2}))
	_, ok = hashMap.Get(&data{value: 2})
	require.False(t, ok)

	// replace conflicting
	v33, ok = hashMap.Get(&data{value: 33})
	require.Equal(t, 33, v33)
	require.True(t, ok)
	replaced, oldValue := hashMap.TryPut(&data{value: 33}, 44)
	require.True(t, replaced)
	require.Equal(t, 33, oldValue)

	// replace non-conflicting
	hashMap.Put(&data{value: 7}, 7)
	replaced, d7 := hashMap.TryPut(&data{value: 7}, 777)
	require.True(t, replaced)
	require.Equal(t, 7, d7)

	// clear
	hashMap.Clear()
	require.Equal(t, 0, hashMap.Size())
	require.True(t, hashMap.IsEmpty())
	_, ok = hashMap.Get(&data{value: 1})
	require.False(t, ok)
	_, ok = hashMap.Get(&data{value: 2})
	require.False(t, ok)
	_, ok = hashMap.Get(&data{value: 33})
	require.False(t, ok)
	_, ok = hashMap.Get(&data{value: 33})
	require.False(t, ok)
}

func Test_OrderedHashMap(t *testing.T) {
	hashMap := hashmap.NewComparableHashMap[int, int]()

	// check empty map
	require.Zero(t, hashMap.Size())
	require.True(t, hashMap.IsEmpty())
	_, ok := hashMap.Get(348957)
	require.False(t, ok)
	ok = hashMap.ContainsKey(23465123)
	require.False(t, ok)

	// add two non-conflicting
	replaced, _ := hashMap.TryPut(1, 1)
	require.False(t, replaced)
	replaced, _ = hashMap.TryPut(2, 2)
	require.False(t, replaced)
	require.Equal(t, 2, hashMap.Size())

	// add two conflicting
	replaced, _ = hashMap.TryPut(3, 3)
	require.False(t, replaced)
	replaced, _ = hashMap.TryPut(33, 33)
	require.False(t, replaced)
	require.Equal(t, 4, hashMap.Size())

	// check exists
	require.True(t, hashMap.ContainsKey(1))
	require.True(t, hashMap.ContainsKey(2))
	require.True(t, hashMap.ContainsKey(3))
	require.True(t, hashMap.ContainsKey(33))
	require.False(t, hashMap.ContainsKey(43))

	// check gets
	v1, ok := hashMap.Get(1)
	require.True(t, ok)
	require.Equal(t, 1, v1)
	v2, ok := hashMap.Get(2)
	require.True(t, ok)
	require.Equal(t, 2, v2)
	v3, ok := hashMap.Get(3)
	require.True(t, ok)
	require.Equal(t, 3, v3)
	v33, ok := hashMap.Get(33)
	require.True(t, ok)
	require.Equal(t, 33, v33)

	// check remove conflicting
	ok, removed := hashMap.TryRemove(3)
	require.True(t, ok)
	require.Equal(t, 3, removed)
	require.Equal(t, 3, hashMap.Size())
	require.False(t, hashMap.ContainsKey(3))
	require.True(t, hashMap.ContainsKey(33))
	_, ok = hashMap.Get(3)
	require.False(t, ok)

	// remove again
	ok, _ = hashMap.TryRemove(3)
	require.False(t, ok)

	// remove non-conflicting
	ok, removed2 := hashMap.TryRemove(2)
	require.True(t, ok)
	require.Equal(t, 2, removed2)
	require.Equal(t, 2, hashMap.Size())
	require.False(t, hashMap.ContainsKey(2))
	_, ok = hashMap.Get(2)
	require.False(t, ok)

	// replace conflicting
	v33, ok = hashMap.Get(33)
	require.Equal(t, 33, v33)
	require.True(t, ok)
	replaced, oldValue := hashMap.TryPut(33, 44)
	require.True(t, replaced)
	require.Equal(t, 33, oldValue)

	// replace non-conflicting
	hashMap.Put(7, 7)
	replaced, d7 := hashMap.TryPut(7, 777)
	require.True(t, replaced)
	require.Equal(t, 7, d7)

	// clear
	hashMap.Clear()
	require.Equal(t, 0, hashMap.Size())
	require.True(t, hashMap.IsEmpty())
	_, ok = hashMap.Get(1)
	require.False(t, ok)
	_, ok = hashMap.Get(2)
	require.False(t, ok)
	_, ok = hashMap.Get(33)
	require.False(t, ok)
	_, ok = hashMap.Get(33)
	require.False(t, ok)
}
func Test_HashableHashMap_Remove(t *testing.T) {
	hashMap := hashmap.NewHashableHashMap[*data, int]()

	// add some elements
	hashMap.Put(&data{value: 1}, 1)
	hashMap.Put(&data{value: 2}, 2)
	hashMap.Put(&data{value: 3}, 3)

	// remove an existing key
	hashMap.Remove(&data{value: 2})
	require.False(t, hashMap.ContainsKey(&data{value: 2}))
	require.Equal(t, 2, hashMap.Size())

	// remove a non-existing key
	hashMap.Remove(&data{value: 4})
	require.Equal(t, 2, hashMap.Size())
}
func Test_TryRemove_KeyNotExists(t *testing.T) {
	hashMap := hashmap.NewHashableHashMap[*data, int]()

	// check empty map
	require.Zero(t, hashMap.Size())
	require.True(t, hashMap.IsEmpty())

	// try remove non-existing key
	removed, removedValue := hashMap.TryRemove(&data{value: 1})
	require.False(t, removed)
	require.Zero(t, removedValue)

	// check map remains empty
	require.Zero(t, hashMap.Size())
	require.True(t, hashMap.IsEmpty())
}
func Test_HashableHashMap_Keys(t *testing.T) {
	hashMap := hashmap.NewHashableHashMap[*data, int]()
	hashMap.Put(&data{value: 1}, 1)
	hashMap.Put(&data{value: 2}, 2)
	hashMap.Put(&data{value: 3}, 3)

	keys := hashMap.Keys()
	require.Len(t, keys, 3)
	require.Contains(t, keys, &data{value: 1})
	require.Contains(t, keys, &data{value: 2})
	require.Contains(t, keys, &data{value: 3})
}

func Test_HashableHashMap_Values(t *testing.T) {
	hashMap := hashmap.NewHashableHashMap[*data, int]()
	hashMap.Put(&data{value: 1}, 1)
	hashMap.Put(&data{value: 2}, 2)
	hashMap.Put(&data{value: 3}, 3)

	values := hashMap.Values()
	require.Len(t, values, 3)
	require.Contains(t, values, 1)
	require.Contains(t, values, 2)
	require.Contains(t, values, 3)
}

func Test_HashableHashMap_Clones(t *testing.T) {
	hashMap := hashmap.NewHashableHashMap[*data, int]()
	hashMap.Put(&data{value: 1}, 1)
	hashMap.Put(&data{value: 2}, 2)
	hashMap.Put(&data{value: 3}, 3)

	clone := hashMap.Clone()
	require.Equal(t, hashMap.Size(), clone.Size())

	// Check if the clone contains the same key-value pairs
	for pair := range hashMap.Iter() {
		value, ok := clone.Get(pair.Key)
		require.True(t, ok)
		require.Equal(t, pair.Value, value)
	}

	// Check if modifying the clone does not affect the original map
	clone.Put(&data{value: 4}, 4)
	require.Equal(t, 3, hashMap.Size())
	require.Equal(t, 4, clone.Size())
}

func Test_HashableHashMap_Iter(t *testing.T) {
	hashMap := hashmap.NewHashableHashMap[*data, int]()
	hashMap.Put(&data{value: 1}, 1)
	hashMap.Put(&data{value: 2}, 2)
	hashMap.Put(&data{value: 3}, 3)

	count := 0
	for pair := range hashMap.Iter() {
		require.Contains(t, hashMap.Keys(), pair.Key)
		require.Contains(t, hashMap.Values(), pair.Value)
		count++
	}

	require.Equal(t, count, hashMap.Size())
}

func Test_HashableHashMap_Filter(t *testing.T) {
	hashMap := hashmap.NewHashableHashMap[*data, int]()
	hashMap.Put(&data{value: 1}, 1)
	hashMap.Put(&data{value: 2}, 2)
	hashMap.Put(&data{value: 3}, 3)
	hashMap.Put(&data{value: 4}, 4)
	hashMap.Put(&data{value: 5}, 5)

	// filter out even values
	filtered := hashMap.Filter(func(key *data) bool {
		return key.value%2 == 0
	})

	require.Equal(t, 2, filtered.Size())
	require.Contains(t, filtered.Keys(), &data{value: 2})
	require.Contains(t, filtered.Keys(), &data{value: 4})
	require.NotContains(t, filtered.Keys(), &data{value: 1})
	require.NotContains(t, filtered.Keys(), &data{value: 3})
	require.NotContains(t, filtered.Keys(), &data{value: 5})
}

func Test_HashableHashMap_Retain(t *testing.T) {
	hashMap := hashmap.NewHashableHashMap[*data, int]()
	hashMap.Put(&data{value: 1}, 1)
	hashMap.Put(&data{value: 2}, 2)
	hashMap.Put(&data{value: 3}, 3)
	hashMap.Put(&data{value: 4}, 4)
	hashMap.Put(&data{value: 5}, 5)

	// retain even values
	set := hashset.NewHashableHashSet(&data{value: 2}, &data{value: 4})
	sieved := hashMap.Retain(set)

	require.Equal(t, 2, sieved.Size())
	require.Contains(t, sieved.Keys(), &data{value: 2})
	require.Contains(t, sieved.Keys(), &data{value: 4})
	require.NotContains(t, sieved.Keys(), &data{value: 1})
	require.NotContains(t, sieved.Keys(), &data{value: 3})
	require.NotContains(t, sieved.Keys(), &data{value: 5})
}
