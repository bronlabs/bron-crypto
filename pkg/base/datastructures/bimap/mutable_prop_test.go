package bimap_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bimap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

// Basic Operations

func TestMutableBiMap_PutGet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		// Generate a value not already in the bimap
		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		value := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "value")

		m.Put(key, value)
		got, exists := m.Get(key)

		require.True(t, exists)
		require.Equal(t, value, got)
	})
}

func TestMutableBiMap_TryPut_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		// Generate unique values
		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		value1 := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "value1")
		usedValues[value1] = true
		value2 := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "value2")

		// Ensure key is not present
		m.Remove(key)

		// First put - should not be a replacement
		replaced1, _ := m.TryPut(key, value1)
		require.False(t, replaced1)
		got1, _ := m.Get(key)
		require.Equal(t, value1, got1)

		// Second put - should be a replacement
		replaced2, oldValue2 := m.TryPut(key, value2)
		require.True(t, replaced2)
		require.Equal(t, value1, oldValue2)

		got2, _ := m.Get(key)
		require.Equal(t, value2, got2)
	})
}

func TestMutableBiMap_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		value := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "value")

		m.Put(key, value)
		require.True(t, m.ContainsKey(key))

		m.Remove(key)
		require.False(t, m.ContainsKey(key))
	})
}

func TestMutableBiMap_TryRemove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		value := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "value")

		// Remove non-existent key
		m.Remove(key)
		removed1, _ := m.TryRemove(key)
		require.False(t, removed1)

		// Add and remove
		m.Put(key, value)
		removed2, oldValue := m.TryRemove(key)
		require.True(t, removed2)
		require.Equal(t, value, oldValue)
		require.False(t, m.ContainsKey(key))
	})
}

func TestMutableBiMap_Clear_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")

		m.Clear()

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
	})
}

func TestMutableBiMap_ContainsKey_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		_, exists := m.Get(key)
		contains := m.ContainsKey(key)

		require.Equal(t, exists, contains)
	})
}

// Reverse Operations - BiMap specific

func TestMutableBiMap_Reverse_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")

		reversed := m.Reverse()

		// Every (k, v) in m should be (v, k) in reversed
		for k, v := range m.Iter() {
			gotKey, exists := reversed.Get(v)
			require.True(t, exists)
			require.Equal(t, k, gotKey)
		}
	})
}

func TestMutableBiMap_ReverseReverse_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")

		doubleReversed := m.Reverse().Reverse()

		// Double reverse should give back equivalent map
		require.Equal(t, m.Size(), doubleReversed.Size())
		for k, v := range m.Iter() {
			got, exists := doubleReversed.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestMutableBiMap_Bidirectional_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := EmptyMutableBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		m.Put(key, value)

		// Forward lookup
		gotValue, exists := m.Get(key)
		require.True(t, exists)
		require.Equal(t, value, gotValue)

		// Reverse lookup
		reversed := m.Reverse()
		gotKey, exists := reversed.Get(value)
		require.True(t, exists)
		require.Equal(t, key, gotKey)
	})
}

// Size Properties

func TestMutableBiMap_Size_PutNew_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Filter(func(k string) bool {
			return !m.ContainsKey(k)
		}).Draw(t, "newKey")

		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		value := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "value")

		sizeBefore := m.Size()
		m.Put(key, value)
		sizeAfter := m.Size()

		require.Equal(t, sizeBefore+1, sizeAfter)
	})
}

func TestMutableBiMap_Size_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := NonEmptyMutableBiMapGenerator().Draw(t, "m")
		keys := m.Keys()
		key := rapid.SampledFrom(keys).Draw(t, "existingKey")

		sizeBefore := m.Size()
		m.Remove(key)
		sizeAfter := m.Size()

		require.Equal(t, sizeBefore-1, sizeAfter)
	})
}

// Collection Operations

func TestMutableBiMap_Keys_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")

		keys := m.Keys()

		require.Len(t, keys, m.Size())
		for _, k := range keys {
			require.True(t, m.ContainsKey(k))
		}
	})
}

func TestMutableBiMap_Values_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")

		values := m.Values()

		require.Len(t, values, m.Size())
		// Values should be unique in a bimap
		uniqueValues := make(map[int]bool)
		for _, v := range values {
			require.False(t, uniqueValues[v], "duplicate value in bimap")
			uniqueValues[v] = true
		}
	})
}

func TestMutableBiMap_Filter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")
		predicate := func(k string) bool { return len(k)%2 == 0 }

		filtered := m.Filter(predicate)

		for k, v := range filtered.Iter() {
			require.True(t, predicate(k))
			originalV, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, originalV, v)
		}
	})
}

func TestMutableBiMap_Retain_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")
		keys := m.Keys()
		if len(keys) == 0 {
			return
		}
		numToRetain := rapid.IntRange(0, len(keys)).Draw(t, "numToRetain")
		keysToRetain := keys[:numToRetain]

		retained := m.Retain(keysToRetain...)

		require.LessOrEqual(t, retained.Size(), len(keysToRetain))
		for k, v := range retained.Iter() {
			originalV, _ := m.Get(k)
			require.Equal(t, originalV, v)
		}
	})
}

// Iteration

func TestMutableBiMap_Iter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")

		visited := make(map[string]int)
		for k, v := range m.Iter() {
			visited[k] = v
		}

		require.Len(t, visited, m.Size())
		for k, v := range visited {
			got, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

// Clone

func TestMutableBiMap_Clone_Equality_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")

		cloned := m.Clone()

		require.Equal(t, m.Size(), cloned.Size())
		for k, v := range m.Iter() {
			got, exists := cloned.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestMutableBiMap_Clone_Independence_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		value := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "value")

		cloned := m.Clone()
		sizeBefore := m.Size()

		// Modify clone
		cloned.Put(key, value)

		// Original should be unchanged (if key was new)
		if !m.ContainsKey(key) {
			require.Equal(t, sizeBefore, m.Size())
		}
	})
}

// Freeze/Unfreeze

func TestMutableBiMap_Freeze_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")

		frozen := m.Freeze()

		require.Equal(t, m.Size(), frozen.Size())
		for k, v := range m.Iter() {
			got, exists := frozen.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestMutableBiMap_FreezeUnfreeze_Roundtrip_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableBiMapGenerator().Draw(t, "m")

		frozen := m.Freeze()
		unfrozen := frozen.Unfreeze()

		require.Equal(t, m.Size(), unfrozen.Size())
		for k, v := range m.Iter() {
			got, exists := unfrozen.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

// Constructor

func TestNewMutableBiMap_NonEmpty_Error_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		key := KeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		// Non-empty key map should error
		keyMap := hashmap.NewComparable[string, int]()
		keyMap.Put(key, value)
		valueMap := hashmap.NewComparable[int, string]()

		_, err := bimap.NewMutableBiMap(keyMap, valueMap)
		require.Error(t, err)
	})
}

// Empty BiMap

func TestMutableBiMap_Empty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := EmptyMutableBiMapGenerator().Draw(t, "m")

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
		require.Empty(t, m.Keys())
		require.Empty(t, m.Values())
	})
}
