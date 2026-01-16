// Package bimap provides bidirectional map implementations for the datastructures interfaces.
package bimap

import (
	"iter"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

// MutableBiMap is a mutable bidirectional map where both keys and values are unique.
// It maintains two internal maps for efficient lookup in both directions.
type MutableBiMap[K any, V any] struct {
	internalMap ds.MutableMap[K, V]
	reverseMap  ds.MutableMap[V, K]
}

// NewMutableBiMap creates a new mutable bidirectional map using the provided empty maps.
// Both emptyKey and emptyValue must be empty maps; returns an error if they are not.
func NewMutableBiMap[K any, V any](emptyKey ds.MutableMap[K, V], emptyValue ds.MutableMap[V, K]) (ds.MutableBiMap[K, V], error) {
	if !emptyKey.IsEmpty() {
		return nil, ds.ErrInvalidSize.WithMessage("key is not empty")
	}
	if !emptyValue.IsEmpty() {
		return nil, ds.ErrInvalidSize.WithMessage("value is not empty")
	}
	return &MutableBiMap[K, V]{
		internalMap: emptyKey,
		reverseMap:  emptyValue,
	}, nil
}

// Reverse returns a view of this bimap with keys and values swapped.
// The returned bimap shares storage with the original.
func (m *MutableBiMap[K, V]) Reverse() ds.MutableBiMap[V, K] {
	return &MutableBiMap[V, K]{
		internalMap: m.reverseMap,
		reverseMap:  m.internalMap,
	}
}

// Freeze returns an immutable snapshot of this bimap.
func (m *MutableBiMap[K, V]) Freeze() ds.BiMap[K, V] {
	return &ImmutableBiMap[K, V]{
		internalMap: m.internalMap.Freeze(),
		reverseMap:  m.reverseMap.Freeze(),
	}
}

// ContainsKey returns true if the key exists in the bimap.
func (m *MutableBiMap[K, V]) ContainsKey(key K) bool {
	return m.internalMap.ContainsKey(key)
}

// Get returns the value associated with the key and whether it exists.
func (m *MutableBiMap[K, V]) Get(l K) (V, bool) {
	return m.internalMap.Get(l)
}

// Retain returns a new bimap containing only entries with the specified keys.
func (m *MutableBiMap[K, V]) Retain(keys ...K) ds.MutableBiMap[K, V] {
	retained := m.internalMap.Retain(keys...)
	reverseMap := m.reverseMap.Clone()
	reverseMap.Clear()
	for key, value := range retained.Iter() {
		reverseMap.Put(value, key)
	}
	return &MutableBiMap[K, V]{
		internalMap: retained,
		reverseMap:  reverseMap,
	}
}

// Filter returns a new bimap containing only entries where the predicate returns true.
func (m *MutableBiMap[K, V]) Filter(predicate func(key K) bool) ds.MutableBiMap[K, V] {
	return &MutableBiMap[K, V]{
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

// Put adds or updates a key-value pair in the bimap.
func (m *MutableBiMap[K, V]) Put(l K, r V) {
	_, _ = m.TryPut(l, r)
}

// TryPut adds or updates a key-value pair, returning whether a value was replaced and the old value.
// If the key already existed, the old value is removed from the reverse map.
func (m *MutableBiMap[K, V]) TryPut(l K, r V) (replaced bool, oldValue V) {
	replaced, oldValue = m.internalMap.TryPut(l, r)
	if replaced {
		// Remove old value from reverse map since it's no longer mapped
		m.reverseMap.Remove(oldValue)
	}
	_, _ = m.reverseMap.TryPut(r, l)
	return replaced, oldValue
}

// Clear removes all entries from the bimap.
func (m *MutableBiMap[_, _]) Clear() {
	m.internalMap.Clear()
	m.reverseMap.Clear()
}

// Size returns the number of entries in the bimap.
func (m *MutableBiMap[_, _]) Size() int {
	return m.internalMap.Size()
}

// IsEmpty returns true if the bimap contains no entries.
func (m *MutableBiMap[_, _]) IsEmpty() bool {
	return m.internalMap.IsEmpty()
}

// Remove deletes the entry with the given key from the bimap.
func (m *MutableBiMap[K, V]) Remove(l K) {
	m.TryRemove(l)
}

// TryRemove deletes the entry with the given key, returning whether it existed and its value.
func (m *MutableBiMap[K, V]) TryRemove(l K) (removed bool, r V) {
	removed, r = m.internalMap.TryRemove(l)
	if removed {
		_, _ = m.reverseMap.TryRemove(r)
	}
	return removed, r
}

// Keys returns a slice of all keys in the bimap.
func (m *MutableBiMap[K, _]) Keys() []K {
	return m.internalMap.Keys()
}

// Values returns a slice of all values in the bimap.
func (m *MutableBiMap[_, V]) Values() []V {
	return m.reverseMap.Keys()
}

// Iter returns an iterator over all key-value pairs.
func (m *MutableBiMap[K, V]) Iter() iter.Seq2[K, V] {
	return m.internalMap.Iter()
}

// Clone returns a mutable copy of this bimap.
func (m *MutableBiMap[K, V]) Clone() ds.MutableBiMap[K, V] {
	return &MutableBiMap[K, V]{
		internalMap: m.internalMap.Clone(),
		reverseMap:  m.reverseMap.Clone(),
	}
}
