package bimap_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/bimap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
)

type dataV struct {
	value uint64
}

func (d *dataV) HashCode() uint64 {
	return d.value % 10
}

func (d *dataV) Equal(rhs *dataV) bool {
	return d.value == rhs.value
}

var _ datastructures.Hashable[*dataV] = (*dataV)(nil)

type dataK struct {
	value uint64
}

func (d *dataK) HashCode() uint64 {
	return d.value % 10
}

func (d *dataK) Equal(rhs *dataK) bool {
	return d.value == rhs.value
}

var _ datastructures.Hashable[*dataK] = (*dataK)(nil)

func Test_Add(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Verify the added data
	result, ok := biMap.Get(data1)
	assert.True(t, ok)
	assert.Equal(t, data2, result)

	// Add more test data
	data3 := &dataK{value: 3}
	data4 := &dataV{value: 4}
	biMap.Put(data3, data4)

	// Verify the added data
	result, ok = biMap.Get(data3)
	assert.True(t, ok)
	assert.Equal(t, data4, result)

	t.Run("test reverse", func(t *testing.T) {
		// Test Reverse method
		reverseMap := biMap.Reverse()

		// Verify the reverse map
		reverseData2, ok := reverseMap.Get(data2)
		assert.True(t, ok)
		assert.Equal(t, data1, reverseData2)

		reverseData4, ok := reverseMap.Get(data4)
		assert.True(t, ok)
		assert.Equal(t, data3, reverseData4)

		// Add more test data for reverse map
		reverseData5 := &dataV{value: 5}
		reverseData6 := &dataK{value: 6}
		reverseMap.Put(reverseData5, reverseData6)

		// Verify the added data in reverse map
		result2, ok := reverseMap.Get(reverseData5)
		assert.True(t, ok)
		assert.Equal(t, reverseData6, result2)

		// Test Reverse of Reverse method
		originalMap := reverseMap.Reverse()

		// Verify the original map
		originalData6, ok := originalMap.Get(reverseData6)
		assert.True(t, ok)
		assert.Equal(t, reverseData5, originalData6)
	})
}
func Test_Clear(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Verify the added data
	result, ok := biMap.Get(data1)
	assert.True(t, ok)
	assert.Equal(t, data2, result)

	// Clear the map
	biMap.Clear()

	// Verify that the map is empty
	_, ok = biMap.Get(data1)
	assert.False(t, ok)
}
func Test_ContainsKey(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Test ContainsKey method
	assert.True(t, biMap.ContainsKey(data1))
	assert.False(t, biMap.ContainsKey(&dataK{value: 3}))
}
func Test_Size(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Verify the size of the map
	assert.Equal(t, 1, biMap.Size())

	// Add more test data
	data3 := &dataK{value: 3}
	data4 := &dataV{value: 4}
	biMap.Put(data3, data4)

	// Verify the size of the map
	assert.Equal(t, 2, biMap.Size())
}

func Test_IsEmpty(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Verify that the map is empty
	assert.True(t, biMap.IsEmpty())

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Verify that the map is not empty
	assert.False(t, biMap.IsEmpty())
}

func Test_TryRemove(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Try to remove an existing key-value pair
	removed, _ := biMap.TryRemove(data1)
	assert.True(t, removed)

	// Verify that the key-value pair is removed
	_, ok := biMap.Get(data1)
	assert.False(t, ok)

	// Try to remove a non-existing key-value pair
	removed, _ = biMap.TryRemove(data1)
	assert.False(t, removed)
}

func Test_Keys(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Get the keys from the map
	keys := biMap.Keys()

	// Verify the keys
	assert.Len(t, keys, 1)
	assert.Contains(t, keys, data1)
}

func Test_Values(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Get the values from the map
	values := biMap.Values()

	// Verify the values
	assert.Len(t, values, 1)
	assert.Contains(t, values, data2)
}
func Test_Iter(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Get the iterator from the map
	iter := biMap.Iter()

	// Verify the iterator
	assert.NotNil(t, iter)

	// Iterate over the map and collect the key-value pairs
	var pairs []datastructures.KeyValuePair[*dataK, *dataV]
	for pair := range iter {
		pairs = append(pairs, pair)
	}

	// Verify the collected key-value pairs
	assert.Len(t, pairs, 1)
	assert.Equal(t, data1, pairs[0].Key)
	assert.Equal(t, data2, pairs[0].Value)
}

func Test_Clone(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Clone the map
	clone := biMap.Clone()

	// Verify the cloned map
	assert.NotNil(t, clone)

	// Verify that the cloned map is equal to the original map
	assert.Equal(t, biMap, clone)

	// Modify the cloned map
	data3 := &dataK{value: 3}
	data4 := &dataV{value: 4}
	clone.Put(data3, data4)

	// Verify that the modified cloned map is not equal to the original map
	assert.NotEqual(t, biMap, clone)
}
func Test_Remove(t *testing.T) {
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	assert.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Remove an existing key-value pair
	biMap.Remove(data1)

	// Verify that the key-value pair is removed
	_, ok := biMap.Get(data1)
	assert.False(t, ok)

	// Remove a non-existing key-value pair
	biMap.Remove(data1)

	// Verify that the map remains unchanged
	_, ok = biMap.Get(data1)
	assert.False(t, ok)
}
