package bimap

import (
	"sync"

	"iter"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ ds.ConcurrentBiMap[any, any] = (*ConcurrentBiMap[any, any])(nil)

type ConcurrentBiMap[K any, V any] struct {
	internalMap ds.BiMap[K, V]
	mu          sync.RWMutex
}

func NewConcurrentBiMap[K any, V any](innerBiMap ds.BiMap[K, V]) *ConcurrentBiMap[K, V] {
	return &ConcurrentBiMap[K, V]{
		internalMap: innerBiMap,
		mu:          sync.RWMutex{},
	}
}

func (m *ConcurrentBiMap[K, V]) Reverse() ds.BiMap[V, K] {
	m.mu.Lock()
	defer m.mu.Unlock()

	return NewConcurrentBiMap(m.internalMap.Reverse())
}

func (m *ConcurrentBiMap[K, V]) ContainsKey(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.internalMap.ContainsKey(key)
}

func (m *ConcurrentBiMap[K, V]) Get(l K) (V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.internalMap.Get(l)
}

func (m *ConcurrentBiMap[K, V]) Retain(keys ds.Set[K]) ds.Map[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.internalMap.Retain(keys)
}

func (m *ConcurrentBiMap[K, V]) Filter(predicate func(key K) bool) ds.Map[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.internalMap.Filter(predicate)
}

func (m *ConcurrentBiMap[K, V]) Put(l K, r V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.internalMap.TryPut(l, r)
}

func (m *ConcurrentBiMap[K, V]) TryPut(l K, r V) (replaced bool, oldValue V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.internalMap.TryPut(l, r)
}

func (m *ConcurrentBiMap[_, _]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.internalMap.Clear()
}

func (m *ConcurrentBiMap[_, _]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.internalMap.Size()
}

func (m *ConcurrentBiMap[_, _]) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.internalMap.IsEmpty()
}

func (m *ConcurrentBiMap[K, V]) Remove(l K) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.internalMap.TryRemove(l)
}

func (m *ConcurrentBiMap[K, V]) TryRemove(l K) (removed bool, r V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.internalMap.TryRemove(l)
}

func (m *ConcurrentBiMap[K, _]) Keys() []K {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.internalMap.Keys()
}

func (m *ConcurrentBiMap[_, V]) Values() []V {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.internalMap.Values()
}

func (m *ConcurrentBiMap[K, V]) Iter() iter.Seq2[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.internalMap.Iter()
}

func (m *ConcurrentBiMap[K, V]) Clone() ds.Map[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	clone, _ := m.internalMap.Clone().(*ConcurrentBiMap[K, V])
	return clone
}

func (m *ConcurrentBiMap[K, V]) MarshalJSON() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result, err := m.internalMap.MarshalJSON()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal json")
	}
	return result, nil
}

func (m *ConcurrentBiMap[K, V]) Compute(key K, remappingFunction func(key K, oldVal V, exists bool) (V, bool)) V {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldValue, oldExist := m.internalMap.Get(key)

	newValue, shouldStore := remappingFunction(key, oldValue, oldExist)

	if shouldStore {
		m.internalMap.Put(key, newValue)
	} else {
		m.internalMap.Remove(key)
	}
	return newValue
}

func (m *ConcurrentBiMap[K, V]) ComputeIfAbsent(key K, mappingFunction func(key K) (V, bool)) V {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldValue, oldExist := m.internalMap.Get(key)

	if !oldExist {
		return oldValue
	}

	newValue, shouldStore := mappingFunction(key)

	if shouldStore {
		m.internalMap.Put(key, newValue)
	}
	return newValue
}

func (m *ConcurrentBiMap[K, V]) ComputeIfPresent(key K, remappingFunction func(key K, oldVal V) (V, bool)) V {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldValue, oldExist := m.internalMap.Get(key)

	if oldExist {
		return oldValue
	}

	newValue, shouldStore := remappingFunction(key, oldValue)

	if shouldStore {
		m.internalMap.Put(key, newValue)
	} else {
		m.internalMap.Remove(key)
	}
	return newValue
}
