package bimap_test

import (
	"pgregory.net/rapid"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bimap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

// Common generators for all bimap property tests

// KeyGenerator generates string keys
func KeyGenerator() *rapid.Generator[string] {
	return rapid.String()
}

// ValueGenerator generates int values
func ValueGenerator() *rapid.Generator[int] {
	return rapid.Int()
}

// UniqueValueGenerator generates unique int values for a bimap context
func UniqueValueGenerator() *rapid.Generator[int] {
	return rapid.Int()
}

// MutableBiMapGenerator generates populated MutableBiMap
func MutableBiMapGenerator() *rapid.Generator[ds.MutableBiMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableBiMap[string, int] {
		m, err := bimap.NewMutableBiMap[string, int](
			hashmap.NewComparable[string, int](),
			hashmap.NewComparable[int, string](),
		)
		if err != nil {
			t.Fatal(err)
		}
		// Generate unique key-value pairs (bimap requires unique values too)
		numEntries := rapid.IntRange(0, 20).Draw(t, "numEntries")
		usedValues := make(map[int]bool)
		for range numEntries {
			key := KeyGenerator().Draw(t, "key")
			value := ValueGenerator().Filter(func(v int) bool {
				return !usedValues[v]
			}).Draw(t, "value")
			usedValues[value] = true
			m.Put(key, value)
		}
		return m
	})
}

// NonEmptyMutableBiMapGenerator generates non-empty MutableBiMap
func NonEmptyMutableBiMapGenerator() *rapid.Generator[ds.MutableBiMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableBiMap[string, int] {
		m, err := bimap.NewMutableBiMap[string, int](
			hashmap.NewComparable[string, int](),
			hashmap.NewComparable[int, string](),
		)
		if err != nil {
			t.Fatal(err)
		}
		numEntries := rapid.IntRange(1, 20).Draw(t, "numEntries")
		usedValues := make(map[int]bool)
		for range numEntries {
			key := KeyGenerator().Draw(t, "key")
			value := ValueGenerator().Filter(func(v int) bool {
				return !usedValues[v]
			}).Draw(t, "value")
			usedValues[value] = true
			m.Put(key, value)
		}
		return m
	})
}

// ImmutableBiMapGenerator generates populated ImmutableBiMap
func ImmutableBiMapGenerator() *rapid.Generator[ds.BiMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) ds.BiMap[string, int] {
		m := MutableBiMapGenerator().Draw(t, "mutable")
		return m.Freeze()
	})
}

// ConcurrentBiMapGenerator generates populated ConcurrentBiMap
func ConcurrentBiMapGenerator() *rapid.Generator[*bimap.ConcurrentBiMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) *bimap.ConcurrentBiMap[string, int] {
		inner := MutableBiMapGenerator().Draw(t, "inner")
		return bimap.NewConcurrentBiMap(inner)
	})
}

// NonEmptyConcurrentBiMapGenerator generates non-empty ConcurrentBiMap
func NonEmptyConcurrentBiMapGenerator() *rapid.Generator[*bimap.ConcurrentBiMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) *bimap.ConcurrentBiMap[string, int] {
		inner := NonEmptyMutableBiMapGenerator().Draw(t, "inner")
		return bimap.NewConcurrentBiMap(inner)
	})
}

// EmptyMutableBiMapGenerator generates empty MutableBiMap
func EmptyMutableBiMapGenerator() *rapid.Generator[ds.MutableBiMap[string, int]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableBiMap[string, int] {
		// Use some random data to satisfy rapid's requirements
		_ = rapid.Bool().Draw(t, "dummy")
		m, err := bimap.NewMutableBiMap[string, int](
			hashmap.NewComparable[string, int](),
			hashmap.NewComparable[int, string](),
		)
		if err != nil {
			t.Fatal(err)
		}
		return m
	})
}
