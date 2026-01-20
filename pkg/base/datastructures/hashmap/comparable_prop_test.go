package hashmap_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

// Generators are defined in generators_test.go

// Basic Operations

func TestComparableHashMap_PutGet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		m.Put(key, value)
		got, exists := m.Get(key)

		require.True(t, exists)
		require.Equal(t, value, got)
	})
}

func TestComparableHashMap_TryPut_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		value1 := ValueGenerator().Draw(t, "value1")
		value2 := ValueGenerator().Draw(t, "value2")

		oldValue, exists := m.Get(key)

		// First put - should not be a replacement
		replaced1, oldValue1 := m.TryPut(key, value1)

		if exists {
			require.Equal(t, exists, replaced1)
			require.Equal(t, oldValue, oldValue1)
		}
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

func TestComparableHashMap_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		m.Put(key, value)
		require.True(t, m.ContainsKey(key))

		m.Remove(key)
		require.False(t, m.ContainsKey(key))
	})
}

func TestComparableHashMap_TryRemove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		// Remove non-existent key
		m.Remove(key) // Ensure key is not present
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

func TestComparableHashMap_Clear_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")

		m.Clear()

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
	})
}

func TestComparableHashMap_ContainsKey_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		_, exists := m.Get(key)
		contains := m.ContainsKey(key)

		require.Equal(t, exists, contains)
	})
}

// Size Properties

func TestComparableHashMap_Size_PutNew_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		key := KeyGenerator().Filter(func(k string) bool {
			return !m.ContainsKey(k)
		}).Draw(t, "newKey")
		value := ValueGenerator().Draw(t, "value")

		sizeBefore := m.Size()
		m.Put(key, value)
		sizeAfter := m.Size()

		require.Equal(t, sizeBefore+1, sizeAfter)
	})
}

func TestComparableHashMap_Size_PutExisting_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := NonEmptyMutableMapGenerator().Draw(t, "m")
		keys := m.Keys()
		key := rapid.SampledFrom(keys).Draw(t, "existingKey")
		value := ValueGenerator().Draw(t, "value")

		sizeBefore := m.Size()
		m.Put(key, value)
		sizeAfter := m.Size()

		require.Equal(t, sizeBefore, sizeAfter)
	})
}

func TestComparableHashMap_Size_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := NonEmptyMutableMapGenerator().Draw(t, "m")
		keys := m.Keys()
		key := rapid.SampledFrom(keys).Draw(t, "existingKey")

		sizeBefore := m.Size()
		m.Remove(key)
		sizeAfter := m.Size()

		require.Equal(t, sizeBefore-1, sizeAfter)
	})
}

// Collection Operations

func TestComparableHashMap_Keys_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")

		keys := m.Keys()

		require.Len(t, keys, m.Size())
		for _, k := range keys {
			require.True(t, m.ContainsKey(k))
		}
	})
}

func TestComparableHashMap_Values_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")

		values := m.Values()

		require.Len(t, values, m.Size())
		// Each value should correspond to some key
		keys := m.Keys()
		for i, k := range keys {
			v, _ := m.Get(k)
			require.Contains(t, values, v, "value %d for key %s should be in values", i, k)
		}
	})
}

func TestComparableHashMap_Filter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		// Filter to keep only keys with even length
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

func TestComparableHashMap_Retain_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		keys := m.Keys()
		if len(keys) == 0 {
			return // Skip empty maps
		}
		// Retain a random subset of keys
		numToRetain := rapid.IntRange(0, len(keys)).Draw(t, "numToRetain")
		keysToRetain := keys[:numToRetain]

		retained := m.Retain(keysToRetain...)

		require.LessOrEqual(t, retained.Size(), len(keysToRetain))
		for k, v := range retained.Iter() {
			require.True(t, slices.Contains(keysToRetain, k))
			originalV, _ := m.Get(k)
			require.Equal(t, originalV, v)
		}
	})
}

// Iteration

func TestComparableHashMap_Iter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")

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

func TestComparableHashMap_Enumerate_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")

		indices := make([]int, 0, m.Size())
		entries := make(map[string]int)
		for i, entry := range m.Enumerate() {
			indices = append(indices, i)
			entries[entry.Key] = entry.Value
		}

		require.Len(t, indices, m.Size())
		// Indices should be 0, 1, 2, ..., n-1
		slices.Sort(indices)
		for i, idx := range indices {
			require.Equal(t, i, idx)
		}
		// All entries should be in map
		for k, v := range entries {
			got, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

// Immutable Filter/Retain

func TestImmutableComparableHashMap_Filter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableMapGenerator().Draw(t, "m")
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

func TestImmutableComparableHashMap_Retain_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableMapGenerator().Draw(t, "m")
		keys := m.Keys()
		if len(keys) == 0 {
			return
		}
		numToRetain := rapid.IntRange(0, len(keys)).Draw(t, "numToRetain")
		keysToRetain := keys[:numToRetain]

		retained := m.Retain(keysToRetain...)

		require.LessOrEqual(t, retained.Size(), len(keysToRetain))
		for k, v := range retained.Iter() {
			require.True(t, slices.Contains(keysToRetain, k))
			originalV, _ := m.Get(k)
			require.Equal(t, originalV, v)
		}
	})
}

// Freeze/Unfreeze

func TestComparableHashMap_Freeze_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")

		frozen := m.Freeze()

		// Type system guarantees frozen is immutable (ds.Map interface)
		require.Equal(t, m.Size(), frozen.Size())
		for k, v := range m.Iter() {
			got, exists := frozen.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestImmutableComparableHashMap_Unfreeze_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableMapGenerator().Draw(t, "m")

		unfrozen := m.Unfreeze()

		// Type system guarantees unfrozen is mutable (ds.MutableMap interface)
		require.Equal(t, m.Size(), unfrozen.Size())
		for k, v := range m.Iter() {
			got, exists := unfrozen.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestComparableHashMap_FreezeUnfreeze_Roundtrip_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")

		roundtrip := m.Freeze().Unfreeze()

		require.Equal(t, m.Size(), roundtrip.Size())
		for k, v := range m.Iter() {
			got, exists := roundtrip.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

// Clone

func TestComparableHashMap_Clone_Equality_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")

		cloned := m.Clone()

		require.Equal(t, m.Size(), cloned.Size())
		for k, v := range m.Iter() {
			got, exists := cloned.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestComparableHashMap_Clone_Independence_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

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

func TestImmutableComparableHashMap_Clone_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableMapGenerator().Draw(t, "m")

		cloned := m.Clone()

		require.Equal(t, m.Size(), cloned.Size())
		for k, v := range m.Iter() {
			got, exists := cloned.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

// Constructors

func TestCollectToComparable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		keys := rapid.SliceOf(KeyGenerator()).Draw(t, "keys")
		values := rapid.SliceOfN(ValueGenerator(), len(keys), len(keys)).Draw(t, "values")

		m, err := hashmap.CollectToComparable(keys, values)

		require.NoError(t, err)
		// Note: duplicate keys mean size may be less than len(keys)
		for _, k := range keys {
			got, exists := m.Get(k)
			require.True(t, exists)
			// Value should be the last one for this key
			lastIdx := -1
			for j := len(keys) - 1; j >= 0; j-- {
				if keys[j] == k {
					lastIdx = j
					break
				}
			}
			require.Equal(t, values[lastIdx], got)
		}
	})
}

func TestCollectToComparable_LengthMismatch_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		keys := rapid.SliceOfN(KeyGenerator(), 1, -1).Draw(t, "keys")
		// Generate values with different length
		valuesLen := rapid.IntRange(0, len(keys)*2).Filter(func(n int) bool {
			return n != len(keys)
		}).Draw(t, "valuesLen")
		values := rapid.SliceOfN(ValueGenerator(), valuesLen, valuesLen).Draw(t, "values")

		_, err := hashmap.CollectToComparable(keys, values)

		require.Error(t, err)
	})
}

func TestCollectToImmutableComparable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		keys := rapid.SliceOf(KeyGenerator()).Draw(t, "keys")
		values := rapid.SliceOfN(ValueGenerator(), len(keys), len(keys)).Draw(t, "values")

		m, err := hashmap.CollectToImmutableComparable(keys, values)

		require.NoError(t, err)
		// Type system guarantees m is immutable (ds.Map interface)
		for _, k := range keys {
			got, exists := m.Get(k)
			require.True(t, exists)
			// Value should be the last one for this key
			lastIdx := -1
			for j := len(keys) - 1; j >= 0; j-- {
				if keys[j] == k {
					lastIdx = j
					break
				}
			}
			require.Equal(t, values[lastIdx], got)
		}
	})
}

func TestNewComparableFromNativeLike_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		native := rapid.MapOf(KeyGenerator(), ValueGenerator()).Draw(t, "native")

		m := hashmap.NewComparableFromNativeLike(native)

		require.Equal(t, len(native), m.Size())
		for k, v := range native {
			got, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestNewImmutableComparableFromNativeLike_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		native := rapid.MapOf(KeyGenerator(), ValueGenerator()).Draw(t, "native")

		m := hashmap.NewImmutableComparableFromNativeLike(native)

		// Type system guarantees m is immutable (ds.Map interface)
		require.Equal(t, len(native), m.Size())
		for k, v := range native {
			got, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

// Immutability Properties

func TestImmutableComparableHashMap_IsImmutable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		entries := rapid.SliceOf(MapEntryGenerator()).Draw(t, "entries")
		m := hashmap.NewImmutableComparable(entries...)
		// Type assert to concrete type to test IsImmutable
		immutable, ok := m.(*hashmap.ImmutableComparableMap[string, int])
		require.True(t, ok)
		require.True(t, immutable.IsImmutable())
	})
}

func TestComparableHashMap_IsImmutable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableMapGenerator().Draw(t, "m")
		require.False(t, m.IsImmutable())
	})
}

// Empty Map Properties

func TestComparableHashMap_Empty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := hashmap.NewComparable[string, int]()

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
		require.Empty(t, m.Keys())
		require.Empty(t, m.Values())
	})
}

func TestCollectToComparable_Empty_Property(t *testing.T) {
	t.Parallel()
	m, err := hashmap.CollectToComparable([]string{}, []int{})

	require.NoError(t, err)
	require.True(t, m.IsEmpty())
}

func TestCollectToImmutableComparable_Empty_Property(t *testing.T) {
	t.Parallel()
	m, err := hashmap.CollectToImmutableComparable([]string{}, []int{})

	require.NoError(t, err)
	require.True(t, m.IsEmpty())
}
