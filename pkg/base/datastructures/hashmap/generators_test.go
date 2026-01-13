package hashmap_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"pgregory.net/rapid"
)

// Common generators for all hashmap property tests

// KeyGenerator generates string keys (comparable type)
func KeyGenerator() *rapid.Generator[string] {
	return rapid.String()
}

// ValueGenerator generates int values
func ValueGenerator() *rapid.Generator[int] {
	return rapid.Int()
}

// MapEntryGenerator generates ds.MapEntry[string, int]
func MapEntryGenerator() *rapid.Generator[ds.MapEntry[string, int]] {
	return rapid.Custom(func(t *rapid.T) ds.MapEntry[string, int] {
		return ds.MapEntry[string, int]{
			Key:   KeyGenerator().Draw(t, "key"),
			Value: ValueGenerator().Draw(t, "value"),
		}
	})
}

// MutableMapGenerator generates populated ComparableHashMap
func MutableMapGenerator() *rapid.Generator[*hashmap.MutableComparableMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) *hashmap.MutableComparableMap[string, int] {
		entries := rapid.SliceOf(MapEntryGenerator()).Draw(t, "entries")
		return hashmap.NewComparable(entries...)
	})
}

// ImmutableMapGenerator generates populated ImmutableComparableHashMap
func ImmutableMapGenerator() *rapid.Generator[ds.Map[string, int]] {
	return rapid.Custom(func(t *rapid.T) ds.Map[string, int] {
		entries := rapid.SliceOf(MapEntryGenerator()).Draw(t, "entries")
		return hashmap.NewImmutableComparable(entries...)
	})
}

// NonEmptyMutableMapGenerator generates non-empty mutable maps
func NonEmptyMutableMapGenerator() *rapid.Generator[*hashmap.MutableComparableMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) *hashmap.MutableComparableMap[string, int] {
		entries := rapid.SliceOfN(MapEntryGenerator(), 1, -1).Draw(t, "entries")
		return hashmap.NewComparable(entries...)
	})
}

// ConcurrentMapGenerator generates populated ConcurrentMap
func ConcurrentMapGenerator() *rapid.Generator[ds.ConcurrentMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) ds.ConcurrentMap[string, int] {
		inner := MutableMapGenerator().Draw(t, "inner")
		return hashmap.NewConcurrentMap[string, int](inner)
	})
}

// NonEmptyConcurrentMapGenerator generates non-empty concurrent maps
func NonEmptyConcurrentMapGenerator() *rapid.Generator[ds.ConcurrentMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) ds.ConcurrentMap[string, int] {
		inner := NonEmptyMutableMapGenerator().Draw(t, "inner")
		return hashmap.NewConcurrentMap[string, int](inner)
	})
}

// HashableKey is a test type that implements ds.Hashable[*HashableKey]
type HashableKey struct {
	Value string
}

func (k *HashableKey) Equal(other *HashableKey) bool {
	return k.Value == other.Value
}

func (k *HashableKey) HashCode() base.HashCode {
	h := base.HashCode(0)
	for _, c := range k.Value {
		h = h.Combine(base.HashCode(c))
	}
	return h
}

// HashableKeyGenerator generates *HashableKey values
func HashableKeyGenerator() *rapid.Generator[*HashableKey] {
	return rapid.Custom(func(t *rapid.T) *HashableKey {
		return &HashableKey{Value: rapid.String().Draw(t, "keyValue")}
	})
}

// HashableMapEntryGenerator generates ds.MapEntry[*HashableKey, int]
func HashableMapEntryGenerator() *rapid.Generator[ds.MapEntry[*HashableKey, int]] {
	return rapid.Custom(func(t *rapid.T) ds.MapEntry[*HashableKey, int] {
		return ds.MapEntry[*HashableKey, int]{
			Key:   HashableKeyGenerator().Draw(t, "key"),
			Value: ValueGenerator().Draw(t, "value"),
		}
	})
}

// MutableHashableMapGenerator generates populated MutableHashableHashMap
func MutableHashableMapGenerator() *rapid.Generator[ds.MutableMap[*HashableKey, int]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableMap[*HashableKey, int] {
		m := hashmap.NewHashable[*HashableKey, int]()
		entries := rapid.SliceOf(HashableMapEntryGenerator()).Draw(t, "entries")
		for _, e := range entries {
			m.Put(e.Key, e.Value)
		}
		return m
	})
}

// ImmutableHashableMapGenerator generates populated ImmutableHashableHashMap
func ImmutableHashableMapGenerator() *rapid.Generator[ds.Map[*HashableKey, int]] {
	return rapid.Custom(func(t *rapid.T) ds.Map[*HashableKey, int] {
		m := MutableHashableMapGenerator().Draw(t, "mutable")
		return m.Freeze()
	})
}

// NonEmptyMutableHashableMapGenerator generates non-empty mutable hashable maps
func NonEmptyMutableHashableMapGenerator() *rapid.Generator[ds.MutableMap[*HashableKey, int]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableMap[*HashableKey, int] {
		m := hashmap.NewHashable[*HashableKey, int]()
		entries := rapid.SliceOfN(HashableMapEntryGenerator(), 1, -1).Draw(t, "entries")
		for _, e := range entries {
			m.Put(e.Key, e.Value)
		}
		return m
	})
}

// Helper for value equality
func IntEq(a, b int) bool {
	return a == b
}
