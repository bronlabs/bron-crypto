package bimap

import (
	"iter"
	"sync"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

// ConcurrentBiMap is a thread-safe wrapper around a MutableBiMap.
// All operations are protected by a read-write mutex.
type ConcurrentBiMap[K any, V any] struct {
	inner ds.MutableBiMap[K, V]
	mu    sync.RWMutex
}

// NewConcurrentBiMap creates a new thread-safe bimap wrapping the given mutable bimap.
func NewConcurrentBiMap[K any, V any](innerBiMap ds.MutableBiMap[K, V]) *ConcurrentBiMap[K, V] {
	return &ConcurrentBiMap[K, V]{
		inner: innerBiMap,
		mu:    sync.RWMutex{},
	}
}

// Reverse returns a thread-safe view of this bimap with keys and values swapped.
func (m *ConcurrentBiMap[K, V]) Reverse() ds.ConcurrentBiMap[V, K] {
	m.mu.Lock()
	defer m.mu.Unlock()

	return NewConcurrentBiMap(m.inner.Reverse())
}

// ContainsKey returns true if the key exists in the bimap.
func (m *ConcurrentBiMap[K, V]) ContainsKey(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.ContainsKey(key)
}

// Get returns the value associated with the key and whether it exists.
func (m *ConcurrentBiMap[K, V]) Get(l K) (V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Get(l)
}

// Retain returns a new concurrent bimap containing only entries with the specified keys.
func (m *ConcurrentBiMap[K, V]) Retain(keys ...K) ds.ConcurrentBiMap[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return NewConcurrentBiMap(m.inner.Retain(keys...))
}

// Filter returns a new concurrent bimap containing only entries where the predicate returns true.
func (m *ConcurrentBiMap[K, V]) Filter(predicate func(key K) bool) ds.ConcurrentBiMap[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return NewConcurrentBiMap(m.inner.Filter(predicate))
}

// Put adds or updates a key-value pair in the bimap.
func (m *ConcurrentBiMap[K, V]) Put(l K, r V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.inner.TryPut(l, r)
}

// TryPut adds or updates a key-value pair, returning whether a value was replaced and the old value.
func (m *ConcurrentBiMap[K, V]) TryPut(l K, r V) (replaced bool, oldValue V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.TryPut(l, r)
}

// Clear removes all entries from the bimap.
func (m *ConcurrentBiMap[_, _]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inner.Clear()
}

// Size returns the number of entries in the bimap.
func (m *ConcurrentBiMap[_, _]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Size()
}

// IsEmpty returns true if the bimap contains no entries.
func (m *ConcurrentBiMap[_, _]) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.IsEmpty()
}

// Remove deletes the entry with the given key from the bimap.
func (m *ConcurrentBiMap[K, V]) Remove(l K) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inner.TryRemove(l)
}

// TryRemove deletes the entry with the given key, returning whether it existed and its value.
func (m *ConcurrentBiMap[K, V]) TryRemove(l K) (removed bool, r V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.TryRemove(l)
}

// Keys returns a slice of all keys in the bimap.
func (m *ConcurrentBiMap[K, _]) Keys() []K {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Keys()
}

// Values returns a slice of all values in the bimap.
func (m *ConcurrentBiMap[_, V]) Values() []V {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Values()
}

// Iter returns an iterator over all key-value pairs.
func (m *ConcurrentBiMap[K, V]) Iter() iter.Seq2[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Iter()
}

// Clone returns a new concurrent bimap with a copy of the data.
func (m *ConcurrentBiMap[K, V]) Clone() ds.ConcurrentBiMap[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return NewConcurrentBiMap(m.inner.Clone())
}

// Compute atomically computes a new value based on the key's current mapping.
// The remappingFunction receives the key, current value (if any), and existence flag,
// returning the new value and whether to store it (false removes the key).
func (m *ConcurrentBiMap[K, V]) Compute(key K, remappingFunction func(key K, oldVal V, exists bool) (V, bool)) V {
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
func (m *ConcurrentBiMap[K, V]) ComputeIfAbsent(key K, mappingFunction func(key K) (V, bool)) V {
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
func (m *ConcurrentBiMap[K, V]) ComputeIfPresent(key K, remappingFunction func(key K, oldVal V) (V, bool)) V {
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
