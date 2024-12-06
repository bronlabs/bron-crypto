package hashmap

import (
	"encoding/json"
	"iter"

	"golang.org/x/exp/maps"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type ComparableHashMap[K comparable, V any] struct {
	inner map[K]V
}

func NewComparableHashMap[K comparable, V any]() ds.Map[K, V] {
	return &ComparableHashMap[K, V]{
		inner: make(map[K]V),
	}
}

func (m *ComparableHashMap[K, V]) Get(key K) (value V, exists bool) {
	v, exists := m.inner[key]
	return v, exists
}

func (m *ComparableHashMap[K, V]) Retain(keys ds.Set[K]) ds.Map[K, V] {
	return m.Filter(keys.Contains)
}

func (m *ComparableHashMap[K, V]) Filter(predicate func(key K) bool) ds.Map[K, V] {
	result := make(map[K]V)
	for k, v := range m.inner {
		if predicate(k) {
			result[k] = v
		}
	}
	return &ComparableHashMap[K, V]{
		inner: result,
	}
}

func (m *ComparableHashMap[K, V]) ContainsKey(key K) bool {
	_, exists := m.Get(key)
	return exists
}

func (m *ComparableHashMap[K, V]) Put(key K, value V) {
	_, _ = m.TryPut(key, value)
}

func (m *ComparableHashMap[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	oldV, oldExists := m.inner[key]
	m.inner[key] = newValue
	return oldExists, oldV
}

func (m *ComparableHashMap[K, V]) Clear() {
	clear(m.inner)
}

func (m *ComparableHashMap[K, V]) Size() int {
	return len(m.inner)
}

func (m *ComparableHashMap[K, V]) IsEmpty() bool {
	return m.Size() == 0
}

func (m *ComparableHashMap[K, V]) Remove(key K) {
	_, _ = m.TryRemove(key)
}

func (m *ComparableHashMap[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	oldValue, oldExists := m.inner[key]
	delete(m.inner, key)
	return oldExists, oldValue
}

func (m *ComparableHashMap[K, V]) Keys() []K {
	return maps.Keys(m.inner)
}

func (m *ComparableHashMap[K, V]) Values() []V {
	return maps.Values(m.inner)
}

func (m *ComparableHashMap[K, V]) Clone() ds.Map[K, V] {
	return &ComparableHashMap[K, V]{
		inner: maps.Clone(m.inner),
	}
}

func (m *ComparableHashMap[K, V]) MarshalJSON() ([]byte, error) {
	serialised, err := json.Marshal(m.inner)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal")
	}
	return serialised, nil
}
func (m *ComparableHashMap[K, V]) UnmarshalJSON(data []byte) error {
	var temp map[K]V
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not json marshal comparable hash map")
	}
	m.inner = temp
	return nil
}

func (m *ComparableHashMap[K, V]) Iter() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for k, v := range m.inner {
			if !yield(k, v) {
				return
			}
		}
	}
}
