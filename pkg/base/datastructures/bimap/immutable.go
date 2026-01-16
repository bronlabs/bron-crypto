package bimap

import (
	"iter"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

// ImmutableBiMap is an immutable bidirectional map where both keys and values are unique.
type ImmutableBiMap[K any, V any] struct {
	internalMap ds.Map[K, V]
	reverseMap  ds.Map[V, K]
}

// Reverse returns a view of this bimap with keys and values swapped.
func (m *ImmutableBiMap[K, V]) Reverse() ds.BiMap[V, K] {
	return &ImmutableBiMap[V, K]{
		internalMap: m.reverseMap,
		reverseMap:  m.internalMap,
	}
}

// Unfreeze returns a mutable copy of this bimap.
func (m *ImmutableBiMap[K, V]) Unfreeze() ds.MutableBiMap[K, V] {
	return &MutableBiMap[K, V]{
		internalMap: m.internalMap.Unfreeze(),
		reverseMap:  m.reverseMap.Unfreeze(),
	}
}

// ContainsKey returns true if the key exists in the bimap.
func (m *ImmutableBiMap[K, V]) ContainsKey(key K) bool {
	return m.internalMap.ContainsKey(key)
}

// Get returns the value associated with the key and whether it exists.
func (m *ImmutableBiMap[K, V]) Get(l K) (V, bool) {
	return m.internalMap.Get(l)
}

// Size returns the number of entries in the bimap.
func (m *ImmutableBiMap[_, _]) Size() int {
	return m.internalMap.Size()
}

// IsEmpty returns true if the bimap contains no entries.
func (m *ImmutableBiMap[_, _]) IsEmpty() bool {
	return m.internalMap.IsEmpty()
}

// Retain returns a new bimap containing only entries with the specified keys.
func (m *ImmutableBiMap[K, V]) Retain(keys ...K) ds.BiMap[K, V] {
	retained := m.internalMap.Retain(keys...).Unfreeze()
	reverseMap := m.reverseMap.Clone().Unfreeze()
	reverseMap.Clear()
	for key, value := range retained.Iter() {
		reverseMap.Put(value, key)
	}
	return &ImmutableBiMap[K, V]{
		internalMap: retained.Freeze(),
		reverseMap:  reverseMap.Freeze(),
	}
}

// Filter returns a new bimap containing only entries where the predicate returns true.
func (m *ImmutableBiMap[K, V]) Filter(predicate func(key K) bool) ds.BiMap[K, V] {
	return &ImmutableBiMap[K, V]{
		internalMap: m.internalMap.Filter(predicate),
		reverseMap: m.reverseMap.Filter(func(value V) bool {
			for k := range m.internalMap.Iter() {
				if predicate(k) {
					return true
				}
			}
			return false
		}),
	}
}

// Keys returns a slice of all keys in the bimap.
func (m *ImmutableBiMap[K, _]) Keys() []K {
	return m.internalMap.Keys()
}

// Values returns a slice of all values in the bimap.
func (m *ImmutableBiMap[_, V]) Values() []V {
	return m.reverseMap.Keys()
}

// Iter returns an iterator over all key-value pairs.
func (m *ImmutableBiMap[K, V]) Iter() iter.Seq2[K, V] {
	return m.internalMap.Iter()
}

// Clone returns a copy of this bimap.
func (m *ImmutableBiMap[K, V]) Clone() ds.BiMap[K, V] {
	return &ImmutableBiMap[K, V]{
		internalMap: m.internalMap.Clone(),
		reverseMap:  m.reverseMap.Clone(),
	}
}
