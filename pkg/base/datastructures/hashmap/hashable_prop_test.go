package hashmap_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

// Basic Operations

func TestMutableHashableHashMap_PutGet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")
		key := HashableKeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		m.Put(key, value)
		got, exists := m.Get(key)

		require.True(t, exists)
		require.Equal(t, value, got)
	})
}

func TestMutableHashableHashMap_TryPut_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")
		key := HashableKeyGenerator().Draw(t, "key")
		value1 := ValueGenerator().Draw(t, "value1")
		value2 := ValueGenerator().Draw(t, "value2")

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

func TestMutableHashableHashMap_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")
		key := HashableKeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		m.Put(key, value)
		require.True(t, m.ContainsKey(key))

		m.Remove(key)
		require.False(t, m.ContainsKey(key))
	})
}

func TestMutableHashableHashMap_TryRemove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")
		key := HashableKeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

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

func TestMutableHashableHashMap_Clear_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")

		m.Clear()

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
	})
}

func TestMutableHashableHashMap_ContainsKey_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")
		key := HashableKeyGenerator().Draw(t, "key")

		_, exists := m.Get(key)
		contains := m.ContainsKey(key)

		require.Equal(t, exists, contains)
	})
}

// Size Properties

func TestMutableHashableHashMap_Size_PutNew_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")
		key := HashableKeyGenerator().Filter(func(k *HashableKey) bool {
			return !m.ContainsKey(k)
		}).Draw(t, "newKey")
		value := ValueGenerator().Draw(t, "value")

		sizeBefore := m.Size()
		m.Put(key, value)
		sizeAfter := m.Size()

		require.Equal(t, sizeBefore+1, sizeAfter)
	})
}

func TestMutableHashableHashMap_Size_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := NonEmptyMutableHashableMapGenerator().Draw(t, "m")
		keys := m.Keys()
		key := rapid.SampledFrom(keys).Draw(t, "existingKey")

		sizeBefore := m.Size()
		m.Remove(key)
		sizeAfter := m.Size()

		require.Equal(t, sizeBefore-1, sizeAfter)
	})
}

// Collection Operations

func TestMutableHashableHashMap_Keys_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")

		keys := m.Keys()

		require.Len(t, keys, m.Size())
		for _, k := range keys {
			require.True(t, m.ContainsKey(k))
		}
	})
}

func TestMutableHashableHashMap_Values_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")

		values := m.Values()

		require.Len(t, values, m.Size())
	})
}

func TestMutableHashableHashMap_Filter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")
		predicate := func(k *HashableKey) bool { return len(k.Value)%2 == 0 }

		filtered := m.Filter(predicate)

		for k, v := range filtered.Iter() {
			require.True(t, predicate(k))
			originalV, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, originalV, v)
		}
	})
}

func TestMutableHashableHashMap_Retain_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")
		keys := m.Keys()
		if len(keys) == 0 {
			return
		}
		numToRetain := rapid.IntRange(0, len(keys)).Draw(t, "numToRetain")
		keysToRetain := keys[:numToRetain]

		retained := m.Retain(keysToRetain...)

		require.LessOrEqual(t, retained.Size(), len(keysToRetain))
		for k, v := range retained.Iter() {
			found := false
			for _, rk := range keysToRetain {
				if rk.Equal(k) {
					found = true
					break
				}
			}
			require.True(t, found)
			originalV, _ := m.Get(k)
			require.Equal(t, originalV, v)
		}
	})
}

// Iteration

func TestMutableHashableHashMap_Iter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")

		count := 0
		for k, v := range m.Iter() {
			got, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
			count++
		}

		require.Equal(t, m.Size(), count)
	})
}

func TestMutableHashableHashMap_Enumerate_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")

		indices := make([]int, 0, m.Size())
		for i, entry := range m.Enumerate() {
			indices = append(indices, i)
			got, exists := m.Get(entry.Key)
			require.True(t, exists)
			require.Equal(t, entry.Value, got)
		}

		require.Len(t, indices, m.Size())
		slices.Sort(indices)
		for i, idx := range indices {
			require.Equal(t, i, idx)
		}
	})
}

// Immutable Filter/Retain

func TestImmutableHashableHashMap_Filter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableHashableMapGenerator().Draw(t, "m")
		predicate := func(k *HashableKey) bool { return len(k.Value)%2 == 0 }

		filtered := m.Filter(predicate)

		for k, v := range filtered.Iter() {
			require.True(t, predicate(k))
			originalV, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, originalV, v)
		}
	})
}

func TestImmutableHashableHashMap_Retain_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableHashableMapGenerator().Draw(t, "m")
		keys := m.Keys()
		if len(keys) == 0 {
			return
		}
		numToRetain := rapid.IntRange(0, len(keys)).Draw(t, "numToRetain")
		keysToRetain := keys[:numToRetain]

		retained := m.Retain(keysToRetain...)

		require.LessOrEqual(t, retained.Size(), len(keysToRetain))
		for k, v := range retained.Iter() {
			found := false
			for _, rk := range keysToRetain {
				if rk.Equal(k) {
					found = true
					break
				}
			}
			require.True(t, found)
			originalV, _ := m.Get(k)
			require.Equal(t, originalV, v)
		}
	})
}

// Freeze/Unfreeze

func TestMutableHashableHashMap_Freeze_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")

		frozen := m.Freeze()

		require.Equal(t, m.Size(), frozen.Size())
		for k, v := range m.Iter() {
			got, exists := frozen.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestImmutableHashableHashMap_Unfreeze_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableHashableMapGenerator().Draw(t, "m")

		unfrozen := m.Unfreeze()

		require.Equal(t, m.Size(), unfrozen.Size())
		for k, v := range m.Iter() {
			got, exists := unfrozen.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestMutableHashableHashMap_FreezeUnfreeze_Roundtrip_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")

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

func TestMutableHashableHashMap_Clone_Equality_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")

		cloned := m.Clone()

		require.Equal(t, m.Size(), cloned.Size())
		for k, v := range m.Iter() {
			got, exists := cloned.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestMutableHashableHashMap_Clone_Independence_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := MutableHashableMapGenerator().Draw(t, "m")
		key := HashableKeyGenerator().Draw(t, "key")
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

func TestImmutableHashableHashMap_Clone_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableHashableMapGenerator().Draw(t, "m")

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

func TestCollectToHashable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		keys := rapid.SliceOf(HashableKeyGenerator()).Draw(t, "keys")
		values := rapid.SliceOfN(ValueGenerator(), len(keys), len(keys)).Draw(t, "values")

		m, err := hashmap.CollectToHashable(keys, values)

		require.NoError(t, err)
		for _, k := range keys {
			_, exists := m.Get(k)
			require.True(t, exists)
		}
	})
}

func TestCollectToHashable_LengthMismatch_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		keys := rapid.SliceOfN(HashableKeyGenerator(), 1, -1).Draw(t, "keys")
		valuesLen := rapid.IntRange(0, len(keys)*2).Filter(func(n int) bool {
			return n != len(keys)
		}).Draw(t, "valuesLen")
		values := rapid.SliceOfN(ValueGenerator(), valuesLen, valuesLen).Draw(t, "values")

		_, err := hashmap.CollectToHashable(keys, values)

		require.Error(t, err)
	})
}

func TestCollectToImmutableHashable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		keys := rapid.SliceOf(HashableKeyGenerator()).Draw(t, "keys")
		values := rapid.SliceOfN(ValueGenerator(), len(keys), len(keys)).Draw(t, "values")

		m, err := hashmap.CollectToImmutableHashable(keys, values)

		require.NoError(t, err)
		for _, k := range keys {
			_, exists := m.Get(k)
			require.True(t, exists)
		}
	})
}

func TestNewHashable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := hashmap.NewHashable[*HashableKey, int]()

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
	})
}

func TestNewImmutableHashable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := hashmap.NewImmutableHashable[*HashableKey, int]()

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
	})
}

// Immutability Properties

func TestImmutableHashableHashMap_IsImmutable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := hashmap.NewHashable[*HashableKey, int]()
		entries := rapid.SliceOf(HashableMapEntryGenerator()).Draw(t, "entries")
		for _, e := range entries {
			m.Put(e.Key, e.Value)
		}
		frozen := m.Freeze()
		immutable, ok := frozen.(*hashmap.ImmutableHashableMap[*HashableKey, int])
		require.True(t, ok)
		require.True(t, immutable.IsImmutable())
	})
}

func TestMutableHashableHashMap_IsImmutable_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := hashmap.NewHashable[*HashableKey, int]()
		mutable, ok := m.(*hashmap.MutableHashableMap[*HashableKey, int])
		require.True(t, ok)
		require.False(t, mutable.IsImmutable())
	})
}

// Empty Map Properties

func TestMutableHashableHashMap_Empty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := hashmap.NewHashable[*HashableKey, int]()

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
		require.Empty(t, m.Keys())
		require.Empty(t, m.Values())
	})
}

// Hash Collision Test - ensure keys with same hash but different values work correctly

func TestMutableHashableHashMap_HashCollision_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := hashmap.NewHashable[*HashableKey, int]()

		// Create two keys that might have same hash (short strings)
		key1 := &HashableKey{Value: "a"}
		key2 := &HashableKey{Value: "b"}
		value1 := ValueGenerator().Draw(t, "value1")
		value2 := ValueGenerator().Draw(t, "value2")

		m.Put(key1, value1)
		m.Put(key2, value2)

		got1, exists1 := m.Get(key1)
		got2, exists2 := m.Get(key2)

		require.True(t, exists1)
		require.True(t, exists2)
		require.Equal(t, value1, got1)
		require.Equal(t, value2, got2)
	})
}
