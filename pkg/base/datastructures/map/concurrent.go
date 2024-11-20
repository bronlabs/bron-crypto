package concurrentMap

import (
	"encoding/json"
	"iter"
	"sync"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ ds.ConcurrentMap[any, any] = (*ConcurrentMap[any, any])(nil)

type ConcurrentMap[K any, V any] struct {
	inner ds.Map[K, V]
	mu    sync.RWMutex
}

func NewConcurrentMap[K any, V any](innerMap ds.Map[K, V]) *ConcurrentMap[K, V] {
	return &ConcurrentMap[K, V]{
		inner: innerMap,
		mu:    sync.RWMutex{},
	}
}

func (m *ConcurrentMap[K, V]) Get(key K) (value V, exists bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Get(key)
}

func (m *ConcurrentMap[K, V]) Retain(keys ds.Set[K]) ds.Map[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.Filter(keys.Contains)
}

func (m *ConcurrentMap[K, V]) Filter(predicate func(key K) bool) ds.Map[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()

	return &ConcurrentMap[K, V]{
		inner: m.inner.Filter(predicate),
		mu:    sync.RWMutex{},
	}
}

func (m *ConcurrentMap[K, V]) ContainsKey(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.ContainsKey(key)
}

func (m *ConcurrentMap[K, V]) Put(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.inner.TryPut(key, value)
}

func (m *ConcurrentMap[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.TryPut(key, newValue)
}

func (m *ConcurrentMap[K, V]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inner.Clear()
}

func (m *ConcurrentMap[K, V]) Clone() ds.Map[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	clone := m.inner.Clone()
	return clone
}

func (m *ConcurrentMap[K, V]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Size()
}

func (m *ConcurrentMap[K, V]) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.IsEmpty()
}

func (m *ConcurrentMap[K, V]) Remove(key K) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = m.inner.TryRemove(key)
}

func (m *ConcurrentMap[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.TryRemove(key)
}

func (m *ConcurrentMap[K, V]) Iter() iter.Seq2[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Iter()
}

func (m *ConcurrentMap[K, V]) Keys() []K {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Keys()
}

func (m *ConcurrentMap[K, V]) Values() []V {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inner.Values()
}

func (m *ConcurrentMap[K, V]) MarshalJSON() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result, err := m.inner.MarshalJSON()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal json")
	}
	return result, nil
}

func (m *ConcurrentMap[K, V]) UnmarshalJSON(data []byte) error {
	var temp ds.Map[K, V]
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not json unmarshal comparable hash map")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inner = temp
	return nil
}

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
