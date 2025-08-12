package bimap

import (
	"encoding/json"
	"iter"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var _ ds.MutableBiMap[int, any] = &BiMap[int, any]{}

type BiMap[K any, V any] struct {
	internalMap ds.MutableMap[K, V]
	reverseMap  ds.MutableMap[V, K]
}

func NewBiMap[K any, V any](emptyKey ds.MutableMap[K, V], emptyValue ds.MutableMap[V, K]) (ds.MutableBiMap[K, V], error) {
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

func (m *BiMap[K, V]) Reverse() ds.MutableBiMap[V, K] {
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

func (m *BiMap[K, V]) Retain(keys ...K) ds.MutableBiMap[K, V] {
	retained := m.internalMap.Retain(keys...)
	reverseMap := m.reverseMap.Clone()
	reverseMap.Clear()
	for key, value := range retained.Iter() {
		reverseMap.Put(value, key)
	}
	return &BiMap[K, V]{
		internalMap: retained,
		reverseMap:  reverseMap,
	}
}

func (m *BiMap[K, V]) Filter(predicate func(key K) bool) ds.MutableBiMap[K, V] {
	return &BiMap[K, V]{
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
	return m.internalMap.Iter()
}

func (m *BiMap[K, V]) Enumerate() iter.Seq2[int, ds.MapEntry[K, V]] {
	return m.internalMap.Enumerate()
}

func (m *BiMap[K, V]) Clone() ds.MutableBiMap[K, V] {
	return &BiMap[K, V]{
		internalMap: m.internalMap.Clone(),
		reverseMap:  m.reverseMap.Clone(),
	}
}

func (m *BiMap[K, V]) IsSubMap(other ds.MutableBiMap[K, V], eq func(a, b V) bool) bool {
	return false
}

func (m *BiMap[K, V]) IsProperSubMap(other ds.MutableBiMap[K, V], eq func(a, b V) bool) bool {
	return false
}

func (m *BiMap[K, V]) IsSuperMap(other ds.MutableBiMap[K, V], eq func(a, b V) bool) bool {
	return other.IsSubMap(m, eq)
}

func (m *BiMap[K, V]) IsProperSuperMap(other ds.MutableBiMap[K, V], eq func(a, b V) bool) bool {
	return other.IsProperSubMap(m, eq)
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
