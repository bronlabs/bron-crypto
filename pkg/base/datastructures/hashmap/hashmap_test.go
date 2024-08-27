package hashmap_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	concurrentMap "github.com/copperexchange/krypton-primitives/pkg/base/datastructures/map"
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	hashMap := hashmap.NewHashableHashMap[*data, int]()

	hashMap.Put(&data{value: 1}, 1)
	hashMap.Put(&data{value: 2}, 2)
	hashMap.Put(&data{value: 3}, 3)

	clone := hashMap.Clone()
	require.Equal(t, hashMap.Size(), clone.Size())

	// Check if the clone contains the same key-value pairs

	for iterator := hashMap.Iterator(); iterator.HasNext(); {
		entry := iterator.Next()
		value, ok := clone.Get(entry.Key)
		require.True(t, ok)
		require.Equal(t, entry.Value, value)
	}

	// Check if modifying the clone does not affect the original map
	clone.Put(&data{value: 4}, 4)
	require.Equal(t, 3, hashMap.Size())
	require.Equal(t, 4, clone.Size())
}

func TestConcurrentMapComputeIfAbset(t *testing.T) {
	t.Parallel()
	inner := hashmap.NewHashableHashMap[*data, int]()
	hashMap := concurrentMap.NewConcurrentMap(inner)

	hashMap.Put(&data{value: 1}, 0)
	hashMap.Put(&data{value: 2}, 0)

	numLoop := 1000

	var wg sync.WaitGroup
	wg.Add(2)
	slice := []*data{
		{value: 3},
		{value: 4},
	}
	go func() {
		defer wg.Done()
		for _, key := range slice {
			for i := 0; i < numLoop; i++ {
				hashMap.ComputeIfAbsent(key, func(k *data) (int, bool) {
					return 1, true
				})
			}
		}
	}()

	go func() {
		defer wg.Done()
		for _, key := range slice {
			for i := 0; i < numLoop; i++ {
				hashMap.ComputeIfAbsent(key, func(k *data) (int, bool) {
					return 1, true
				})
			}
		}
	}()

	wg.Wait()

	_, oldExist1 := hashMap.Get(&data{value: 4})
	require.True(t, oldExist1)
	_, oldExist2 := hashMap.Get(&data{value: 3})
	require.True(t, oldExist2)
}

func TestConcurrentMapCompute(t *testing.T) {
	t.Parallel()
	inner := hashmap.NewHashableHashMap[*data, int]()
	hashMap := concurrentMap.NewConcurrentMap(inner)

	hashMap.Put(&data{value: 1}, 0)
	hashMap.Put(&data{value: 2}, 0)

	numLoop := 10000

	var wg sync.WaitGroup
	wg.Add(2)
	keys := hashMap.Keys()

	go func() {
		defer wg.Done()
		for _, key := range keys {
			for i := 0; i < numLoop; i++ {
				hashMap.Compute(key, func(k *data, v int, b bool) (int, bool) {
					if b {
						return v + 1, true
					} else {
						return 0, false
					}
				})
			}
		}
	}()

	go func() {
		defer wg.Done()
		for _, key := range keys {
			for i := 0; i < numLoop; i++ {
				hashMap.Compute(key, func(k *data, v int, b bool) (int, bool) {
					if b {
						return v - 1, true
					} else {
						return 0, false
					}
				})
			}
		}
	}()

	wg.Wait()

	value1, _ := hashMap.Get(&data{value: 1})
	require.Equal(t, 0, value1)
	value2, _ := hashMap.Get(&data{value: 2})
	require.Equal(t, 0, value2)
}

func TestConcurrentMapComputeIfPresent(t *testing.T) {
	t.Parallel()
	inner := hashmap.NewHashableHashMap[*data, int]()
	hashMap := concurrentMap.NewConcurrentMap(inner)

	hashMap.Put(&data{value: 1}, 1)
	hashMap.Put(&data{value: 2}, 2)

	numLoop := 1000

	var wg sync.WaitGroup
	wg.Add(2)
	slice := []*data{
		{value: 3},
		{value: 4},
		{value: 3},
		{value: 4},
	}
	go func() {
		defer wg.Done()
		for _, key := range slice {
			for i := 0; i < numLoop; i++ {
				hashMap.ComputeIfPresent(key, func(k *data, v int) (int, bool) {
					return v + 1, true
				})
			}
		}
	}()

	go func() {
		defer wg.Done()
		for _, key := range slice {
			for i := 0; i < numLoop; i++ {
				hashMap.ComputeIfPresent(key, func(k *data, v int) (int, bool) {
					return v - 1, true
				})
			}
		}
	}()

	wg.Wait()

	value1, _ := hashMap.Get(&data{value: 1})
	require.Equal(t, 1, value1)
	value2, _ := hashMap.Get(&data{value: 2})
	require.Equal(t, 2, value2)
	value3, _ := hashMap.Get(&data{value: 3})
	require.Equal(t, 0, value3)
	value4, _ := hashMap.Get(&data{value: 4})
	require.Equal(t, 0, value4)
}
