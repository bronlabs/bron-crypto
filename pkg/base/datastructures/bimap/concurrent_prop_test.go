package bimap_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bimap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

// Basic Operations

func TestConcurrentBiMap_PutGet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

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

func TestConcurrentBiMap_TryPut_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

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

		m.Remove(key)

		replaced1, _ := m.TryPut(key, value1)
		require.False(t, replaced1)

		replaced2, oldValue2 := m.TryPut(key, value2)
		require.True(t, replaced2)
		require.Equal(t, value1, oldValue2)
	})
}

func TestConcurrentBiMap_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
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

func TestConcurrentBiMap_TryRemove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		value := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "value")

		m.Remove(key)
		removed1, _ := m.TryRemove(key)
		require.False(t, removed1)

		m.Put(key, value)
		removed2, oldValue := m.TryRemove(key)
		require.True(t, removed2)
		require.Equal(t, value, oldValue)
	})
}

func TestConcurrentBiMap_Clear_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")

		m.Clear()

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
	})
}

func TestConcurrentBiMap_Clone_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")

		cloned := m.Clone()

		require.Equal(t, m.Size(), cloned.Size())
		for k, v := range m.Iter() {
			got, exists := cloned.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

// Reverse Operations

func TestConcurrentBiMap_Reverse_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")

		reversed := m.Reverse()

		for k, v := range m.Iter() {
			gotKey, exists := reversed.Get(v)
			require.True(t, exists)
			require.Equal(t, k, gotKey)
		}
	})
}

func TestConcurrentBiMap_ReverseReverse_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")

		doubleReversed := m.Reverse().Reverse()

		require.Equal(t, m.Size(), doubleReversed.Size())
		for k, v := range m.Iter() {
			got, exists := doubleReversed.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

// Size Properties

func TestConcurrentBiMap_Size_PutNew_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
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

func TestConcurrentBiMap_Size_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := NonEmptyConcurrentBiMapGenerator().Draw(t, "m")
		keys := m.Keys()
		key := rapid.SampledFrom(keys).Draw(t, "existingKey")

		sizeBefore := m.Size()
		m.Remove(key)
		sizeAfter := m.Size()

		require.Equal(t, sizeBefore-1, sizeAfter)
	})
}

// Collection Operations

func TestConcurrentBiMap_Keys_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")

		keys := m.Keys()

		require.Len(t, keys, m.Size())
	})
}

func TestConcurrentBiMap_Values_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")

		values := m.Values()

		require.Len(t, values, m.Size())
	})
}

func TestConcurrentBiMap_Filter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
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

func TestConcurrentBiMap_Retain_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
		keys := m.Keys()
		if len(keys) == 0 {
			return
		}
		numToRetain := rapid.IntRange(0, len(keys)).Draw(t, "numToRetain")
		keysToRetain := keys[:numToRetain]

		retained := m.Retain(keysToRetain...)

		require.LessOrEqual(t, retained.Size(), len(keysToRetain))
	})
}

// Iteration

func TestConcurrentBiMap_Iter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")

		visited := make(map[string]int)
		for k, v := range m.Iter() {
			visited[k] = v
		}

		require.Len(t, visited, m.Size())
	})
}

// Compute Operations

func TestConcurrentBiMap_Compute_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		newValue := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "newValue")

		m.Remove(key)

		result := m.Compute(key, func(k string, oldVal int, exists bool) (int, bool) {
			return newValue, true
		})

		require.Equal(t, newValue, result)
		got, exists := m.Get(key)
		require.True(t, exists)
		require.Equal(t, newValue, got)
	})
}

func TestConcurrentBiMap_Compute_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
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

		m.Compute(key, func(k string, oldVal int, exists bool) (int, bool) {
			return 0, false
		})

		require.False(t, m.ContainsKey(key))
	})
}

func TestConcurrentBiMap_ComputeIfAbsent_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		newValue := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "newValue")

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

func TestConcurrentBiMap_ComputeIfAbsent_Exists_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		existingValue := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "existingValue")
		usedValues[existingValue] = true
		newValue := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "newValue")

		// Add key first
		m.Put(key, existingValue)

		// ComputeIfAbsent should return existing value without computing
		computed := false
		result := m.ComputeIfAbsent(key, func(k string) (int, bool) {
			computed = true
			return newValue, true
		})

		require.False(t, computed)
		require.Equal(t, existingValue, result)
		got, _ := m.Get(key)
		require.Equal(t, existingValue, got)
	})
}

func TestConcurrentBiMap_ComputeIfPresent_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		usedValues := make(map[int]bool)
		for _, v := range m.Values() {
			usedValues[v] = true
		}
		existingValue := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "existingValue")
		usedValues[existingValue] = true
		newValue := ValueGenerator().Filter(func(v int) bool {
			return !usedValues[v]
		}).Draw(t, "newValue")

		// Add key first
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

func TestConcurrentBiMap_ComputeIfPresent_Absent_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ConcurrentBiMapGenerator().Draw(t, "m")
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

func TestConcurrentBiMap_ConcurrentPut_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		inner, _ := bimap.NewMutableBiMap[string, int](
			hashmap.NewComparable[string, int](),
			hashmap.NewComparable[int, string](),
		)
		m := bimap.NewConcurrentBiMap(inner)

		// Generate unique key-value pairs
		numOps := rapid.IntRange(10, 50).Draw(t, "numOps")
		keys := make([]string, numOps)
		values := make([]int, numOps)
		usedValues := make(map[int]bool)

		for i := range numOps {
			keys[i] = KeyGenerator().Draw(t, "key")
			values[i] = ValueGenerator().Filter(func(v int) bool {
				return !usedValues[v]
			}).Draw(t, "value")
			usedValues[values[i]] = true
		}

		var wg sync.WaitGroup
		for i := range numOps {
			wg.Add(1)
			go func(k string, v int) {
				defer wg.Done()
				m.Put(k, v)
			}(keys[i], values[i])
		}
		wg.Wait()

		// Map should have some entries
		require.GreaterOrEqual(t, m.Size(), 1)
	})
}

func TestConcurrentBiMap_ConcurrentGetPut_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		inner, _ := bimap.NewMutableBiMap[string, int](
			hashmap.NewComparable[string, int](),
			hashmap.NewComparable[int, string](),
		)
		m := bimap.NewConcurrentBiMap(inner)
		key := KeyGenerator().Draw(t, "key")
		numOps := rapid.IntRange(10, 50).Draw(t, "numOps")

		var wg sync.WaitGroup
		for i := range numOps {
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

// Empty BiMap

func TestConcurrentBiMap_Empty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		_ = rapid.Bool().Draw(t, "dummy")
		inner, _ := bimap.NewMutableBiMap[string, int](
			hashmap.NewComparable[string, int](),
			hashmap.NewComparable[int, string](),
		)
		m := bimap.NewConcurrentBiMap(inner)

		require.True(t, m.IsEmpty())
		require.Equal(t, 0, m.Size())
		require.Empty(t, m.Keys())
		require.Empty(t, m.Values())
	})
}
