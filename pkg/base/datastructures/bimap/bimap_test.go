package bimap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bimap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
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
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Verify the added data
	result, ok := biMap.Get(data1)
	require.True(t, ok)
	require.Equal(t, data2, result)

	// Add more test data
	data3 := &dataK{value: 3}
	data4 := &dataV{value: 4}
	biMap.Put(data3, data4)

	// Verify the added data
	result, ok = biMap.Get(data3)
	require.True(t, ok)
	require.Equal(t, data4, result)

	t.Run("test reverse", func(t *testing.T) {
		t.Parallel()
		// Test Reverse method
		reverseMap := biMap.Reverse()

		// Verify the reverse map
		reverseData2, ok := reverseMap.Get(data2)
		require.True(t, ok)
		require.Equal(t, data1, reverseData2)

		reverseData4, ok := reverseMap.Get(data4)
		require.True(t, ok)
		require.Equal(t, data3, reverseData4)

		// Add more test data for reverse map
		reverseData5 := &dataV{value: 5}
		reverseData6 := &dataK{value: 6}
		reverseMap.Put(reverseData5, reverseData6)

		// Verify the added data in reverse map
		result2, ok := reverseMap.Get(reverseData5)
		require.True(t, ok)
		require.Equal(t, reverseData6, result2)

		// Test Reverse of Reverse method
		originalMap := reverseMap.Reverse()

		// Verify the original map
		originalData6, ok := originalMap.Get(reverseData6)
		require.True(t, ok)
		require.Equal(t, reverseData5, originalData6)
	})
}
func Test_Clear(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Verify the added data
	result, ok := biMap.Get(data1)
	require.True(t, ok)
	require.Equal(t, data2, result)

	// Clear the map
	biMap.Clear()

	// Verify that the map is empty
	_, ok = biMap.Get(data1)
	require.False(t, ok)
}
func Test_ContainsKey(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Test ContainsKey method
	require.True(t, biMap.ContainsKey(data1))
	require.False(t, biMap.ContainsKey(&dataK{value: 3}))
}
func Test_Size(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Verify the size of the map
	require.Equal(t, 1, biMap.Size())

	// Add more test data
	data3 := &dataK{value: 3}
	data4 := &dataV{value: 4}
	biMap.Put(data3, data4)

	// Verify the size of the map
	require.Equal(t, 2, biMap.Size())
}

func Test_IsEmpty(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Verify that the map is empty
	require.True(t, biMap.IsEmpty())

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Verify that the map is not empty
	require.False(t, biMap.IsEmpty())
}

func Test_TryRemove(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Try to remove an existing key-value pair
	removed, _ := biMap.TryRemove(data1)
	require.True(t, removed)

	// Verify that the key-value pair is removed
	_, ok := biMap.Get(data1)
	require.False(t, ok)

	// Try to remove a non-existing key-value pair
	removed, _ = biMap.TryRemove(data1)
	require.False(t, removed)
}

func Test_Keys(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Get the keys from the map
	keys := biMap.Keys()

	// Verify the keys
	require.Len(t, keys, 1)
	require.Contains(t, keys, data1)
}

func Test_Values(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Get the values from the map
	values := biMap.Values()

	// Verify the values
	require.Len(t, values, 1)
	require.Contains(t, values, data2)
}
func Test_Iter(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	var pairs []datastructures.MapEntry[*dataK, *dataV]
	// Iterate over the map and collect the key-value pairs
	for key, value := range biMap.Iter() {
		pairs = append(pairs, datastructures.MapEntry[*dataK, *dataV]{Key: key, Value: value})
	}

	// Verify the collected key-value pairs
	require.Len(t, pairs, 1)
	require.Equal(t, data1, pairs[0].Key)
	require.Equal(t, data2, pairs[0].Value)
}

func Test_Clone(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Clone the map
	clone := biMap.Clone()

	// Verify the cloned map
	require.NotNil(t, clone)

	// Verify that the cloned map is equal to the original map
	require.Equal(t, biMap, clone)

	// Modify the cloned map
	data3 := &dataK{value: 3}
	data4 := &dataV{value: 4}
	clone.Put(data3, data4)

	// Verify that the modified cloned map is not equal to the original map
	require.NotEqual(t, biMap, clone)
}
func Test_Remove(t *testing.T) {
	t.Parallel()
	emptyKey := hashmap.NewHashableHashMap[*dataK, *dataV]()
	emptyValue := hashmap.NewHashableHashMap[*dataV, *dataK]()

	biMap, err := bimap.NewBiMap(emptyKey, emptyValue)
	require.NoError(t, err)

	// Add test data
	data1 := &dataK{value: 1}
	data2 := &dataV{value: 2}
	biMap.Put(data1, data2)

	// Remove an existing key-value pair
	biMap.Remove(data1)

	// Verify that the key-value pair is removed
	_, ok := biMap.Get(data1)
	require.False(t, ok)

	// Remove a non-existing key-value pair
	biMap.Remove(data1)

	// Verify that the map remains unchanged
	_, ok = biMap.Get(data1)
	require.False(t, ok)
}
