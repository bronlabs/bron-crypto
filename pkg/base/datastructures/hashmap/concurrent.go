package hashmap

import (
	"iter"
	"sync"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

// ConcurrentMap is a thread-safe wrapper around a MutableMap.
// All operations are protected by a read-write mutex.
type ConcurrentMap[K any, V any] struct {
	inner ds.MutableMap[K, V]
	mu    sync.RWMutex
}

// NewConcurrentMap creates a new thread-safe map wrapping the given mutable map.
func NewConcurrentMap[K any, V any](innerMap ds.MutableMap[K, V]) ds.ConcurrentMap[K, V] {
	return &ConcurrentMap[K, V]{
		inner: innerMap,
		mu:    sync.RWMutex{},
	}
}

// Get returns the value associated with the key and whether it exists.
func (m *ConcurrentMap[K, V]) Get(key K) (value V, exists bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Get(key)
}

// Retain returns a new concurrent map containing only entries with the specified keys.
func (m *ConcurrentMap[K, V]) Retain(keys ...K) ds.ConcurrentMap[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &ConcurrentMap[K, V]{
		inner: m.inner.Retain(keys...),
		mu:    sync.RWMutex{},
	}
}

// Filter returns a new concurrent map containing only entries where the predicate returns true.
func (m *ConcurrentMap[K, V]) Filter(predicate func(key K) bool) ds.ConcurrentMap[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()

	return &ConcurrentMap[K, V]{
		inner: m.inner.Filter(predicate),
		mu:    sync.RWMutex{},
	}
}

// ContainsKey returns true if the key exists in the map.
func (m *ConcurrentMap[K, V]) ContainsKey(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.ContainsKey(key)
}

// Put adds or updates a key-value pair in the map.
func (m *ConcurrentMap[K, V]) Put(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.inner.TryPut(key, value)
}

// TryPut adds or updates a key-value pair, returning whether a value was replaced and the old value.
func (m *ConcurrentMap[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.TryPut(key, newValue)
}

// Clear removes all entries from the map.
func (m *ConcurrentMap[K, V]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inner.Clear()
}

// Clone returns a new concurrent map with a copy of the data.
func (m *ConcurrentMap[K, V]) Clone() ds.ConcurrentMap[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return NewConcurrentMap(m.inner.Clone())
}

// Size returns the number of entries in the map.
func (m *ConcurrentMap[K, V]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Size()
}

// IsEmpty returns true if the map contains no entries.
func (m *ConcurrentMap[K, V]) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.IsEmpty()
}

// Remove deletes the entry with the given key from the map.
func (m *ConcurrentMap[K, V]) Remove(key K) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.inner.TryRemove(key)
}

// TryRemove deletes the entry with the given key, returning whether it existed and its value.
func (m *ConcurrentMap[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.TryRemove(key)
}

// Iter returns an iterator over all key-value pairs.
func (m *ConcurrentMap[K, V]) Iter() iter.Seq2[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Iter()
}

// Enumerate returns an iterator with index and MapEntry pairs.
func (m *ConcurrentMap[K, V]) Enumerate() iter.Seq2[int, ds.MapEntry[K, V]] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Enumerate()
}

// Keys returns a slice of all keys in the map.
func (m *ConcurrentMap[K, V]) Keys() []K {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Keys()
}

// Values returns a slice of all values in the map.
func (m *ConcurrentMap[K, V]) Values() []V {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Values()
}

// Compute atomically computes a new value based on the key's current mapping.
// The remappingFunction receives the key, current value (if any), and existence flag,
// returning the new value and whether to store it (false removes the key).
func (m *ConcurrentMap[K, V]) Compute(key K, remappingFunction func(key K, oldVal V, ifExist bool) (V, bool)) V {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldValue, oldExist := m.inner.Get(key)

	newValue, shouldStore := remappingFunction(key, oldValue, oldExist)

	if shouldStore {
		m.inner.Put(key, newValue)
	} else {
		m.inner.Remove(key)
	}
	return newValue
}

// ComputeIfAbsent atomically computes a value only if the key is not present.
// The mappingFunction returns the value to store and whether to store it.
// If the key exists, returns the current value without calling mappingFunction.
func (m *ConcurrentMap[K, V]) ComputeIfAbsent(key K, mappingFunction func(key K) (V, bool)) V {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldValue, oldExist := m.inner.Get(key)

	if oldExist {
		return oldValue
	}

	newValue, shouldStore := mappingFunction(key)

	if shouldStore {
		m.inner.Put(key, newValue)
	}

	return newValue
}

// ComputeIfPresent atomically computes a new value only if the key is present.
// The remappingFunction returns the new value and whether to keep it (false removes the key).
// If the key is absent, returns the zero value without calling remappingFunction.
func (m *ConcurrentMap[K, V]) ComputeIfPresent(key K, remappingFunction func(key K, oldVal V) (V, bool)) V {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldValue, oldExist := m.inner.Get(key)

	if !oldExist {
		return oldValue
	}

	newValue, shouldStore := remappingFunction(key, oldValue)

	if shouldStore {
		m.inner.Put(key, newValue)
	} else {
		m.inner.Remove(key)
	}
	return newValue
}
