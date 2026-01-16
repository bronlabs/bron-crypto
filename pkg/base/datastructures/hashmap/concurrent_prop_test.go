package hashmap_test

import (
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

// Basic Operations

func TestConcurrentMap_PutGet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		m.Put(key, value)
		got, exists := m.Get(key)

		require.True(t, exists)
		require.Equal(t, value, got)
	})
}

func TestConcurrentMap_TryPut_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
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

func TestConcurrentMap_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		m.Put(key, value)
		require.True(t, m.ContainsKey(key))

		m.Remove(key)
		require.False(t, m.ContainsKey(key))
	})
}

func TestConcurrentMap_TryRemove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
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

func TestConcurrentMap_Clear_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")

		m.Clear()

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
	})
}

func TestConcurrentMap_ContainsKey_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		_, exists := m.Get(key)
		contains := m.ContainsKey(key)

		require.Equal(t, exists, contains)
	})
}

// Size Properties

func TestConcurrentMap_Size_PutNew_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
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

func TestConcurrentMap_Size_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := NonEmptyConcurrentMapGenerator().Draw(t, "m")
		keys := m.Keys()
		key := rapid.SampledFrom(keys).Draw(t, "existingKey")

		sizeBefore := m.Size()
		m.Remove(key)
		sizeAfter := m.Size()

		require.Equal(t, sizeBefore-1, sizeAfter)
	})
}

// Collection Operations

func TestConcurrentMap_Keys_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")

		keys := m.Keys()

		require.Equal(t, m.Size(), len(keys))
		for _, k := range keys {
			require.True(t, m.ContainsKey(k))
		}
	})
}

func TestConcurrentMap_Values_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")

		values := m.Values()

		require.Equal(t, m.Size(), len(values))
	})
}

func TestConcurrentMap_Filter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
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

func TestConcurrentMap_Retain_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
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

// Iteration

func TestConcurrentMap_Iter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")

		visited := make(map[string]int)
		for k, v := range m.Iter() {
			visited[k] = v
		}

		require.Equal(t, m.Size(), len(visited))
		for k, v := range visited {
			got, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestConcurrentMap_Enumerate_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")

		indices := make([]int, 0, m.Size())
		entries := make(map[string]int)
		for i, entry := range m.Enumerate() {
			indices = append(indices, i)
			entries[entry.Key] = entry.Value
		}

		require.Equal(t, m.Size(), len(indices))
		slices.Sort(indices)
		for i, idx := range indices {
			require.Equal(t, i, idx)
		}
	})
}

// Clone

func TestConcurrentMap_Clone_Equality_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")

		cloned := m.Clone()

		require.Equal(t, m.Size(), cloned.Size())
		for k, v := range m.Iter() {
			got, exists := cloned.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestConcurrentMap_Clone_Independence_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
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

// Compute Operations

func TestConcurrentMap_Compute_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		newValue := ValueGenerator().Draw(t, "newValue")

		// Compute should set value when shouldStore is true
		result := m.Compute(key, func(k string, oldVal int, exists bool) (int, bool) {
			return newValue, true
		})

		require.Equal(t, newValue, result)
		got, exists := m.Get(key)
		require.True(t, exists)
		require.Equal(t, newValue, got)
	})
}

func TestConcurrentMap_Compute_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		value := ValueGenerator().Draw(t, "value")

		// Add key first
		m.Put(key, value)
		require.True(t, m.ContainsKey(key))

		// Compute with shouldStore=false should remove
		m.Compute(key, func(k string, oldVal int, exists bool) (int, bool) {
			return 0, false
		})

		require.False(t, m.ContainsKey(key))
	})
}

func TestConcurrentMap_ComputeIfAbsent_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		newValue := ValueGenerator().Draw(t, "newValue")

		// Remove key to ensure it's absent
		m.Remove(key)

		// ComputeIfAbsent should compute and store when key is absent
		result := m.ComputeIfAbsent(key, func(k string) (int, bool) {
			return newValue, true
		})

		require.Equal(t, newValue, result)
		got, exists := m.Get(key)
		require.True(t, exists)
		require.Equal(t, newValue, got)
	})
}

func TestConcurrentMap_ComputeIfAbsent_Exists_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		existingValue := ValueGenerator().Draw(t, "existingValue")
		newValue := ValueGenerator().Draw(t, "newValue")

		// Set key first
		m.Put(key, existingValue)

		// ComputeIfAbsent should return existing value without computing
		result := m.ComputeIfAbsent(key, func(k string) (int, bool) {
			return newValue, true
		})

		require.Equal(t, existingValue, result)
		got, _ := m.Get(key)
		require.Equal(t, existingValue, got)
	})
}

func TestConcurrentMap_ComputeIfPresent_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")
		existingValue := ValueGenerator().Draw(t, "existingValue")
		newValue := ValueGenerator().Draw(t, "newValue")

		// Set key first
		m.Put(key, existingValue)

		// ComputeIfPresent should compute when key exists
		result := m.ComputeIfPresent(key, func(k string, oldVal int) (int, bool) {
			require.Equal(t, existingValue, oldVal)
			return newValue, true
		})

		require.Equal(t, newValue, result)
		got, _ := m.Get(key)
		require.Equal(t, newValue, got)
	})
}

func TestConcurrentMap_ComputeIfPresent_Absent_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		// Remove key to ensure it's absent
		m.Remove(key)

		computed := false
		m.ComputeIfPresent(key, func(k string, oldVal int) (int, bool) {
			computed = true
			return 999, true
		})

		// Should not compute when key is absent
		require.False(t, computed)
		require.False(t, m.ContainsKey(key))
	})
}

// Concurrency Tests

func TestConcurrentMap_ConcurrentPut_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		inner := hashmap.NewComparable[string, int]()
		m := hashmap.NewConcurrentMap(inner)
		keys := rapid.SliceOfN(KeyGenerator(), 10, 100).Draw(t, "keys")

		var wg sync.WaitGroup
		for i, key := range keys {
			wg.Add(1)
			go func(k string, v int) {
				defer wg.Done()
				m.Put(k, v)
			}(key, i)
		}
		wg.Wait()

		// All unique keys should be present
		uniqueKeys := make(map[string]bool)
		for _, k := range keys {
			uniqueKeys[k] = true
		}
		require.Equal(t, len(uniqueKeys), m.Size())
	})
}

func TestConcurrentMap_ConcurrentGetPut_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		inner := hashmap.NewComparable[string, int]()
		m := hashmap.NewConcurrentMap(inner)
		key := KeyGenerator().Draw(t, "key")
		numOps := rapid.IntRange(10, 50).Draw(t, "numOps")

		var wg sync.WaitGroup
		for i := 0; i < numOps; i++ {
			wg.Add(2)
			go func(v int) {
				defer wg.Done()
				m.Put(key, v)
			}(i)
			go func() {
				defer wg.Done()
				m.Get(key)
			}()
		}
		wg.Wait()

		// Key should exist after all operations
		require.True(t, m.ContainsKey(key))
	})
}

// Empty Map Properties

func TestConcurrentMap_Empty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		inner := hashmap.NewComparable[string, int]()
		m := hashmap.NewConcurrentMap(inner)

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
		require.Empty(t, m.Keys())
		require.Empty(t, m.Values())
	})
}

// Constructor Test

func TestNewConcurrentMap_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		inner := MutableMapGenerator().Draw(t, "inner")
		m := hashmap.NewConcurrentMap(inner)

		// Verify all entries from inner are accessible
		require.Equal(t, inner.Size(), m.Size())
		for k, v := range inner.Iter() {
			got, exists := m.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}
