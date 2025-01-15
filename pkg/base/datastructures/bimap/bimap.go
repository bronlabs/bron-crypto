package bimap

import (
	"encoding/json"
	"iter"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var _ ds.BiMap[int, any] = &BiMap[int, any]{}

type BiMap[K any, V any] struct {
	internalMap ds.Map[K, V]
	reverseMap  ds.Map[V, K]
}

func NewBiMap[K any, V any](emptyKey ds.Map[K, V], emptyValue ds.Map[V, K]) (ds.BiMap[K, V], error) {
	if !emptyKey.IsEmpty() {
		return nil, errs.NewSize("key is not empty")
	}
	if !emptyValue.IsEmpty() {
		return nil, errs.NewSize("value is not empty")
	}
	return &BiMap[K, V]{
		internalMap: emptyKey,
		reverseMap:  emptyValue,
	}, nil
}

func (m *BiMap[K, V]) Reverse() ds.BiMap[V, K] {
	return &BiMap[V, K]{
		internalMap: m.reverseMap,
		reverseMap:  m.internalMap,
	}
}

func (m *BiMap[K, V]) ContainsKey(key K) bool {
	return m.internalMap.ContainsKey(key)
}

func (m *BiMap[K, V]) Get(l K) (V, bool) {
	return m.internalMap.Get(l)
}

func (m *BiMap[K, V]) Retain(keys ds.Set[K]) ds.Map[K, V] {
	return m.internalMap.Retain(keys)
}

func (m *BiMap[K, V]) Filter(predicate func(key K) bool) ds.Map[K, V] {
	return m.internalMap.Filter(predicate)
}

func (m *BiMap[K, V]) Put(l K, r V) {
	_, _ = m.TryPut(l, r)
}

func (m *BiMap[K, V]) TryPut(l K, r V) (replaced bool, oldValue V) {
	replaced, oldValue = m.internalMap.TryPut(l, r)
	_, _ = m.reverseMap.TryPut(r, l)
	return replaced, oldValue
}

func (m *BiMap[_, _]) Clear() {
	m.internalMap.Clear()
	m.reverseMap.Clear()
}

func (m *BiMap[_, _]) Size() int {
	return m.internalMap.Size()
}

func (m *BiMap[_, _]) IsEmpty() bool {
	return m.internalMap.IsEmpty()
}

func (m *BiMap[K, V]) Remove(l K) {
	m.TryRemove(l)
}

func (m *BiMap[K, V]) TryRemove(l K) (removed bool, r V) {
	removed, r = m.internalMap.TryRemove(l)
	if removed {
		_, _ = m.reverseMap.TryRemove(r)
	}
	return removed, r
}

func (m *BiMap[K, _]) Keys() []K {
	return m.internalMap.Keys()
}

func (m *BiMap[_, V]) Values() []V {
	return m.reverseMap.Keys()
}

func (m *BiMap[K, V]) Iter() iter.Seq2[K, V] {
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

func (m *BiMap[K, V]) Clone() ds.Map[K, V] {
	return &BiMap[K, V]{
		internalMap: m.internalMap.Clone(),
		reverseMap:  m.reverseMap.Clone(),
	}
}

func (m *BiMap[K, V]) MarshalJSON() ([]byte, error) {
	type temp struct {
		Key   json.RawMessage
		Value json.RawMessage
	}
	keyJson, err := m.internalMap.MarshalJSON()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal key")
	}
	valueJson, err := m.reverseMap.MarshalJSON()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal value")
	}
	x := &temp{
		Key:   keyJson,
		Value: valueJson,
	}
	serialised, err := json.Marshal(x)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal")
	}
	return serialised, nil
}
