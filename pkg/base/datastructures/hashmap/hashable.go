package hashmap

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

// HashableEntry represents a key-value pair where the key implements Hashable.
type HashableEntry[K ds.Hashable[K], V any] ds.MapEntry[K, V]

// HashableMapping is the internal storage for hashable maps, using hash codes as bucket keys.
type HashableMapping[K ds.Hashable[K], V any] map[base.HashCode][]*HashableEntry[K, V]

// TryPut adds or updates a key-value pair, returning whether a value was replaced and the old value.
func (m HashableMapping[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	hashCode := key.HashCode()
	entries, exists := m[hashCode]
	if !exists {
		m[hashCode] = []*HashableEntry[K, V]{
			{
				Key:   key,
				Value: newValue,
			},
		}
		return false, *new(V)
	}

	for _, v := range entries {
		if v.Key.Equal(key) {
			oldValue := v.Value
			v.Value = newValue
			return true, oldValue
		}
	}

	m[hashCode] = append(m[hashCode], &HashableEntry[K, V]{
		Key:   key,
		Value: newValue,
	})
	return false, *new(V)
}

// TryRemove deletes the entry with the given key, returning whether it existed and its value.
func (m HashableMapping[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	var nilValue V

	entries, ok := m[key.HashCode()]
	if !ok {
		return false, nilValue
	}

	idx := -1
	for i, e := range entries {
		if e.Key.Equal(key) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return false, nilValue
	}

	removedValue = entries[idx].Value
	entries[idx] = entries[len(entries)-1]
	newEntries := entries[:len(entries)-1]
	if len(newEntries) == 0 {
		delete(m, key.HashCode())
	} else {
		m[key.HashCode()] = newEntries
	}
	return true, removedValue
}

// HashMapTrait provides common functionality for hashable map implementations.
type HashMapTrait[K ds.Hashable[K], V any] struct {
	inner HashableMapping[K, V]
}

// Get returns the value associated with the key and whether it exists.
func (m HashMapTrait[K, V]) Get(key K) (value V, exists bool) {
	hashCode := key.HashCode()
	values, ok := m.inner[hashCode]
	if !ok {
		return *new(V), false
	}
	for _, e := range values {
		if e.Key.Equal(key) {
			return e.Value, true
		}
	}

	return *new(V), false
}

// ContainsKey returns true if the key exists in the map.
func (m HashMapTrait[K, V]) ContainsKey(key K) bool {
	for _, e := range m.inner[key.HashCode()] {
		if key.Equal(e.Key) {
			return true
		}
	}
	return false
}

// IsEmpty returns true if the map contains no entries.
func (m HashMapTrait[K, V]) IsEmpty() bool {
	return len(m.inner) == 0
}

// Size returns the number of entries in the map.
func (m HashMapTrait[K, V]) Size() int {
	size := 0
	for _, v := range m.inner {
		size += len(v)
	}
	return size
}

// Keys returns a slice of all keys in the map.
func (m HashMapTrait[K, V]) Keys() []K {
	var keys []K
	for _, entries := range m.inner {
		for _, entry := range entries {
			keys = append(keys, entry.Key)
		}
	}
	return keys
}

// Values returns a slice of all values in the map.
func (m HashMapTrait[K, V]) Values() []V {
	result := make([]V, 0)
	for _, value := range m.Iter() {
		result = append(result, value)
	}
	return result
}

// Iter returns an iterator over all key-value pairs.
func (m HashMapTrait[K, V]) Iter() iter.Seq2[K, V] {
	keys := m.Keys()
	return func(yield func(K, V) bool) {
		for _, key := range keys {
			value, _ := m.Get(key)
			if !yield(key, value) {
				return
			}
		}
	}
}

// Enumerate returns an iterator with index and MapEntry pairs.
func (m HashMapTrait[K, V]) Enumerate() iter.Seq2[int, ds.MapEntry[K, V]] {
	return func(yield func(int, ds.MapEntry[K, V]) bool) {
		i := 0
		for key, value := range m.Iter() {
			if !yield(i, ds.MapEntry[K, V]{Key: key, Value: value}) {
				return
			}
			i++
		}
	}
}

// NewImmutableHashable creates a new empty immutable map for hashable key types.
func NewImmutableHashable[K ds.Hashable[K], V any]() ds.Map[K, V] {
	return &ImmutableHashableMap[K, V]{
		HashMapTrait[K, V]{
			inner: make(HashableMapping[K, V]),
		},
	}
}

// CollectToImmutableHashable creates a new immutable map from parallel slices of keys and values.
// Returns an error if the slices have different lengths.
func CollectToImmutableHashable[K ds.Hashable[K], V any](xs []K, ys []V) (ds.Map[K, V], error) {
	m, err := CollectToHashable(xs, ys)
	if err != nil {
		return nil, err
	}
	return m.Freeze(), nil
}

// ImmutableHashableMap is an immutable hash map for hashable key types.
type ImmutableHashableMap[K ds.Hashable[K], V any] struct {
	HashMapTrait[K, V]
}

// IsImmutable returns true as this is an immutable map.
func (m ImmutableHashableMap[K, V]) IsImmutable() bool {
	return true
}

// Unfreeze returns a mutable copy of this map.
func (m ImmutableHashableMap[K, V]) Unfreeze() ds.MutableMap[K, V] {
	return &MutableHashableMap[K, V]{
		HashMapTrait[K, V]{
			inner: m.inner,
		},
	}
}

// Clone returns a copy of this map.
func (m ImmutableHashableMap[K, V]) Clone() ds.Map[K, V] {
	inner := make(HashableMapping[K, V])
	for code, entries := range m.inner {
		inner[code] = make([]*HashableEntry[K, V], len(entries))
		for i, e := range entries {
			inner[code][i] = &HashableEntry[K, V]{
				Key:   e.Key,
				Value: e.Value,
			}
		}
	}
	return &ImmutableHashableMap[K, V]{
		HashMapTrait[K, V]{
			inner: inner,
		},
	}
}

// Filter returns a new map containing only entries where the predicate returns true.
func (m ImmutableHashableMap[K, V]) Filter(predicate func(key K) bool) ds.Map[K, V] {
	inner := make(HashableMapping[K, V])
	for _, entries := range m.inner {
		for _, e := range entries {
			if predicate(e.Key) {
				inner.TryPut(e.Key, e.Value)
			}
		}
	}
	return &ImmutableHashableMap[K, V]{
		HashMapTrait[K, V]{
			inner: inner,
		},
	}
}

// Retain returns a new map containing only entries with the specified keys.
func (m ImmutableHashableMap[K, V]) Retain(keys ...K) ds.Map[K, V] {
	return m.Filter(func(key K) bool {
		for _, k := range keys {
			if k.Equal(key) {
				return true
			}
		}
		return false
	})
}

// NewHashable creates a new empty mutable map for hashable key types.
func NewHashable[K ds.Hashable[K], V any]() ds.MutableMap[K, V] {
	return &MutableHashableMap[K, V]{
		HashMapTrait[K, V]{
			inner: make(HashableMapping[K, V]),
		},
	}
}

// CollectToHashable creates a new mutable map from parallel slices of keys and values.
// Returns an error if the slices have different lengths.
func CollectToHashable[K ds.Hashable[K], V any](xs []K, ys []V) (ds.MutableMap[K, V], error) {
	if len(xs) != len(ys) {
		return nil, ds.ErrInvalidSize.WithMessage("xs and ys must have the same length")
	}
	m := NewHashable[K, V]()
	for i := range xs {
		m.Put(xs[i], ys[i])
	}
	return m, nil
}

// MutableHashableMap is a mutable hash map for hashable key types.
type MutableHashableMap[K ds.Hashable[K], V any] struct {
	HashMapTrait[K, V]
}

// IsImmutable returns false as this is a mutable map.
func (m MutableHashableMap[K, V]) IsImmutable() bool {
	return false
}

// Freeze returns an immutable snapshot of this map.
func (m MutableHashableMap[K, V]) Freeze() ds.Map[K, V] {
	return &ImmutableHashableMap[K, V]{
		HashMapTrait[K, V]{
			inner: m.inner,
		},
	}
}

// Clone returns a mutable copy of this map.
func (m MutableHashableMap[K, V]) Clone() ds.MutableMap[K, V] {
	inner := make(HashableMapping[K, V])
	for code, entries := range m.inner {
		inner[code] = make([]*HashableEntry[K, V], len(entries))
		for i, e := range entries {
			inner[code][i] = &HashableEntry[K, V]{
				Key:   e.Key,
				Value: e.Value,
			}
		}
	}
	return &MutableHashableMap[K, V]{
		HashMapTrait[K, V]{
			inner: inner,
		},
	}
}

// Put adds or updates a key-value pair in the map.
func (m MutableHashableMap[K, V]) Put(key K, value V) {
	_, _ = m.TryPut(key, value)
}

// TryPut adds or updates a key-value pair, returning whether a value was replaced and the old value.
func (m MutableHashableMap[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	return m.inner.TryPut(key, newValue)
}

// Clear removes all entries from the map.
func (m MutableHashableMap[K, V]) Clear() {
	clear(m.inner)
}

// Remove deletes the entry with the given key from the map.
func (m MutableHashableMap[K, V]) Remove(key K) {
	_, _ = m.TryRemove(key)
}

// TryRemove deletes the entry with the given key, returning whether it existed and its value.
func (m MutableHashableMap[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	return m.inner.TryRemove(key)
}

// Filter returns a new map containing only entries where the predicate returns true.
func (m MutableHashableMap[K, V]) Filter(predicate func(key K) bool) ds.MutableMap[K, V] {
	inner := make(HashableMapping[K, V])
	for _, entries := range m.inner {
		for _, e := range entries {
			if predicate(e.Key) {
				inner.TryPut(e.Key, e.Value)
			}
		}
	}
	return &MutableHashableMap[K, V]{
		HashMapTrait[K, V]{
			inner: inner,
		},
	}
}

// Retain returns a new map containing only entries with the specified keys.
func (m MutableHashableMap[K, V]) Retain(keys ...K) ds.MutableMap[K, V] {
	return m.Filter(func(key K) bool {
		for _, k := range keys {
			if k.Equal(key) {
				return true
			}
		}
		return false
	})
}
