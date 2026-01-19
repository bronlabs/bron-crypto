// Package hashmap provides hash-based map implementations for the datastructures interfaces.
package hashmap

import (
	"iter"

	"golang.org/x/exp/maps"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

// NativeMap is a type alias for Go's built-in map with additional methods
// to satisfy common map interface requirements.
type NativeMap[K comparable, V any] map[K]V

// Get returns the value associated with the key and whether it exists.
func (m NativeMap[K, V]) Get(key K) (value V, exists bool) {
	v, exists := m[key]
	return v, exists
}

// ContainsKey returns true if the key exists in the map.
func (m NativeMap[K, V]) ContainsKey(key K) bool {
	_, exists := m.Get(key)
	return exists
}

// Put adds or updates a key-value pair in the map.
func (m NativeMap[K, V]) Put(key K, value V) {
	_, _ = m.TryPut(key, value)
}

// TryPut adds or updates a key-value pair, returning whether a value was replaced and the old value.
func (m NativeMap[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	oldV, oldExists := m[key]
	m[key] = newValue
	return oldExists, oldV
}

// Clear removes all entries from the map.
func (m NativeMap[K, V]) Clear() {
	clear(m)
}

// Size returns the number of entries in the map.
func (m NativeMap[K, V]) Size() int {
	return len(m)
}

// IsEmpty returns true if the map contains no entries.
func (m NativeMap[K, V]) IsEmpty() bool {
	return len(m) == 0
}

// Remove deletes the entry with the given key from the map.
func (m NativeMap[K, V]) Remove(key K) {
	_, _ = m.TryRemove(key)
}

// TryRemove deletes the entry with the given key, returning whether it existed and its value.
func (m NativeMap[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	oldValue, oldExists := m[key]
	delete(m, key)
	return oldExists, oldValue
}

// Keys returns a slice of all keys in the map.
func (m NativeMap[K, V]) Keys() []K {
	return maps.Keys(m)
}

// Values returns a slice of all values in the map.
func (m NativeMap[K, V]) Values() []V {
	return maps.Values(m)
}

// Iter returns an iterator over all key-value pairs.
func (m NativeMap[K, V]) Iter() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for k, v := range m {
			if !yield(k, v) {
				return
			}
		}
	}
}

// Enumerate returns an iterator with index and MapEntry pairs.
func (m NativeMap[K, V]) Enumerate() iter.Seq2[int, ds.MapEntry[K, V]] {
	return func(yield func(int, ds.MapEntry[K, V]) bool) {
		i := 0
		for k, v := range m {
			if !yield(i, ds.MapEntry[K, V]{Key: k, Value: v}) {
				return
			}
			i++
		}
	}
}

// ImmutableComparableMap is an immutable hash map for comparable key types.
type ImmutableComparableMap[K comparable, V any] struct {
	inner NativeMap[K, V]
}

// NewImmutableComparable creates a new immutable map from the given entries.
func NewImmutableComparable[K comparable, V any](xs ...ds.MapEntry[K, V]) ds.Map[K, V] {
	out := make(NativeMap[K, V])
	for _, entry := range xs {
		out[entry.Key] = entry.Value
	}
	return &ImmutableComparableMap[K, V]{inner: out}
}

// NewImmutableComparableFromNativeLike creates a new immutable map by copying from a native Go map.
func NewImmutableComparableFromNativeLike[K comparable, V any, T ~map[K]V](arg T) ds.Map[K, V] {
	out := make(NativeMap[K, V])
	if arg != nil {
		maps.Copy(out, arg)
	}
	return &ImmutableComparableMap[K, V]{inner: out}
}

// CollectToImmutableComparable creates a new immutable map from parallel slices of keys and values.
// Returns an error if the slices have different lengths.
func CollectToImmutableComparable[K comparable, V any](xs []K, ys []V) (ds.Map[K, V], error) {
	if len(xs) == 0 && len(ys) == 0 {
		return &ImmutableComparableMap[K, V]{inner: make(NativeMap[K, V])}, nil
	}
	if len(xs) != len(ys) {
		return nil, ds.ErrInvalidSize.WithMessage("xs and ys must have the same length")
	}
	out := make(NativeMap[K, V])
	for i, x := range xs {
		out[x] = ys[i]
	}
	return &ImmutableComparableMap[K, V]{inner: out}, nil
}

// IsImmutable returns true as this is an immutable map.
func (ImmutableComparableMap[K, V]) IsImmutable() bool {
	return true
}

// Unfreeze returns a mutable copy of this map.
func (m ImmutableComparableMap[K, V]) Unfreeze() ds.MutableMap[K, V] {
	return NewComparableFromNativeLike(m.inner)
}

// Get returns the value associated with the key and whether it exists.
func (m ImmutableComparableMap[K, V]) Get(key K) (value V, exists bool) {
	return m.inner.Get(key)
}

// Filter returns a new map containing only entries where the predicate returns true.
func (m ImmutableComparableMap[K, V]) Filter(predicate func(key K) bool) ds.Map[K, V] {
	result := make(NativeMap[K, V])
	for k, v := range m.inner {
		if predicate(k) {
			result[k] = v
		}
	}
	return &ImmutableComparableMap[K, V]{inner: result}
}

// Retain returns a new map containing only entries with the specified keys.
func (m ImmutableComparableMap[K, V]) Retain(keys ...K) ds.Map[K, V] {
	return m.Filter(func(key K) bool {
		for _, k := range keys {
			if k == key {
				return true
			}
		}
		return false
	})
}

// ContainsKey returns true if the key exists in the map.
func (m ImmutableComparableMap[K, V]) ContainsKey(key K) bool {
	return m.inner.ContainsKey(key)
}

// IsEmpty returns true if the map contains no entries.
func (m ImmutableComparableMap[K, V]) IsEmpty() bool {
	return m.Size() == 0
}

// Size returns the number of entries in the map.
func (m ImmutableComparableMap[K, V]) Size() int {
	return m.inner.Size()
}

// Keys returns a slice of all keys in the map.
func (m ImmutableComparableMap[K, V]) Keys() []K {
	return m.inner.Keys()
}

// Values returns a slice of all values in the map.
func (m ImmutableComparableMap[K, V]) Values() []V {
	return m.inner.Values()
}

// Clone returns a copy of this map.
func (m ImmutableComparableMap[K, V]) Clone() ds.Map[K, V] {
	return NewImmutableComparableFromNativeLike(m.inner)
}

// Iter returns an iterator over all key-value pairs.
func (m ImmutableComparableMap[K, V]) Iter() iter.Seq2[K, V] {
	return m.inner.Iter()
}

// Enumerate returns an iterator with index and MapEntry pairs.
func (m ImmutableComparableMap[K, V]) Enumerate() iter.Seq2[int, ds.MapEntry[K, V]] {
	return m.inner.Enumerate()
}

// NewComparable creates a new mutable map from the given entries.
func NewComparable[K comparable, V any](xs ...ds.MapEntry[K, V]) *MutableComparableMap[K, V] {
	out := make(NativeMap[K, V])
	for _, entry := range xs {
		out[entry.Key] = entry.Value
	}
	return &MutableComparableMap[K, V]{out}
}

// CollectToComparable creates a new mutable map from parallel slices of keys and values.
// Returns an error if the slices have different lengths.
func CollectToComparable[K comparable, V any](xs []K, ys []V) (ds.MutableMap[K, V], error) {
	if len(xs) == 0 && len(ys) == 0 {
		return &MutableComparableMap[K, V]{make(NativeMap[K, V])}, nil
	}
	if len(xs) != len(ys) {
		return nil, ds.ErrInvalidSize.WithMessage("xs and ys must have the same length")
	}
	out := make(NativeMap[K, V])
	for i, x := range xs {
		out[x] = ys[i]
	}
	return &MutableComparableMap[K, V]{out}, nil
}

// NewComparableFromNativeLike creates a new mutable map by copying from a native Go map.
func NewComparableFromNativeLike[K comparable, V any, T ~map[K]V](arg T) ds.MutableMap[K, V] {
	out := make(NativeMap[K, V])
	if arg == nil {
		return &MutableComparableMap[K, V]{out}
	}
	maps.Copy(out, arg)
	return &MutableComparableMap[K, V]{out}
}

// MutableComparableMap is a mutable hash map for comparable key types.
type MutableComparableMap[K comparable, V any] struct {
	NativeMap[K, V]
}

// IsImmutable returns false as this is a mutable map.
func (MutableComparableMap[K, V]) IsImmutable() bool {
	return false
}

// Freeze returns an immutable snapshot of this map.
func (m MutableComparableMap[K, V]) Freeze() ds.Map[K, V] {
	return &ImmutableComparableMap[K, V]{
		inner: maps.Clone(m.NativeMap),
	}
}

// Clone returns a mutable copy of this map.
func (m MutableComparableMap[K, V]) Clone() ds.MutableMap[K, V] {
	return &MutableComparableMap[K, V]{maps.Clone(m.NativeMap)}
}

// Filter returns a new map containing only entries where the predicate returns true.
func (m MutableComparableMap[K, V]) Filter(predicate func(key K) bool) ds.MutableMap[K, V] {
	result := make(NativeMap[K, V])
	for k, v := range m.NativeMap {
		if predicate(k) {
			result[k] = v
		}
	}
	return &MutableComparableMap[K, V]{result}
}

// Retain returns a new map containing only entries with the specified keys.
func (m MutableComparableMap[K, V]) Retain(keys ...K) ds.MutableMap[K, V] {
	return m.Filter(func(key K) bool {
		for _, k := range keys {
			if k == key {
				return true
			}
		}
		return false
	})
}

// ToNative returns a copy of the map data as a native Go map.
func (m *MutableComparableMap[K, V]) ToNative() map[K]V {
	out := make(map[K]V)
	for k, v := range m.NativeMap {
		out[k] = v
	}
	return out
}
