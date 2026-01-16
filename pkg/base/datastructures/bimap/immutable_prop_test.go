package bimap_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// Basic Operations

func TestImmutableBiMap_Get_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")
		key := KeyGenerator().Draw(t, "key")

		got, exists := m.Get(key)
		containsKey := m.ContainsKey(key)

		require.Equal(t, exists, containsKey)
		if exists {
			// Verify via iteration
			found := false
			for k, v := range m.Iter() {
				if k == key {
					require.Equal(t, v, got)
					found = true
					break
				}
			}
			require.True(t, found)
		}
	})
}

func TestImmutableBiMap_Unfreeze_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")

		unfrozen := m.Unfreeze()

		require.Equal(t, m.Size(), unfrozen.Size())
		for k, v := range m.Iter() {
			got, exists := unfrozen.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

func TestImmutableBiMap_Clone_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")

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

func TestImmutableBiMap_Reverse_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")

		reversed := m.Reverse()

		for k, v := range m.Iter() {
			gotKey, exists := reversed.Get(v)
			require.True(t, exists)
			require.Equal(t, k, gotKey)
		}
	})
}

func TestImmutableBiMap_ReverseReverse_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")

		doubleReversed := m.Reverse().Reverse()

		require.Equal(t, m.Size(), doubleReversed.Size())
		for k, v := range m.Iter() {
			got, exists := doubleReversed.Get(k)
			require.True(t, exists)
			require.Equal(t, v, got)
		}
	})
}

// Size

func TestImmutableBiMap_Size_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		mutable := MutableBiMapGenerator().Draw(t, "mutable")
		frozen := mutable.Freeze()

		require.Equal(t, mutable.Size(), frozen.Size())
	})
}

func TestImmutableBiMap_IsEmpty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")

		require.Equal(t, m.Size() == 0, m.IsEmpty())
	})
}

// Collection Operations

func TestImmutableBiMap_Keys_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")

		keys := m.Keys()

		require.Equal(t, m.Size(), len(keys))
		for _, k := range keys {
			require.True(t, m.ContainsKey(k))
		}
	})
}

func TestImmutableBiMap_Values_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")

		values := m.Values()

		require.Equal(t, m.Size(), len(values))
		// Values should be unique in a bimap
		uniqueValues := make(map[int]bool)
		for _, v := range values {
			require.False(t, uniqueValues[v], "duplicate value in bimap")
			uniqueValues[v] = true
		}
	})
}

func TestImmutableBiMap_Filter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")
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

func TestImmutableBiMap_Retain_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")
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

func TestImmutableBiMap_Iter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		m := ImmutableBiMapGenerator().Draw(t, "m")

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
