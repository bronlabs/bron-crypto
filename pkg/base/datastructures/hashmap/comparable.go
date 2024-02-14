package hashmap

import (
	"encoding/json"

	"golang.org/x/exp/maps"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type ComparableHashMap[K comparable, V any] map[K]V

func NewComparableHashMap[K comparable, V any]() ds.HashMap[K, V] {
	return make(ComparableHashMap[K, V])
}

func (m ComparableHashMap[K, V]) Get(key K) (value V, exists bool) {
	v, exists := m[key]
	return v, exists
}

func (m ComparableHashMap[K, V]) ContainsKey(key K) bool {
	_, exists := m.Get(key)
	return exists
}

func (m ComparableHashMap[K, V]) Put(key K, value V) {
	_, _ = m.TryPut(key, value)
}

func (m ComparableHashMap[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	oldV, oldExists := m[key]
	m[key] = newValue
	return oldExists, oldV
}

func (m ComparableHashMap[K, V]) Clear() {
	// TODO: use clear keyword in go 1.21
	maps.Clear(m)
}

func (m ComparableHashMap[K, V]) Size() int {
	return len(m)
}

func (m ComparableHashMap[K, V]) IsEmpty() bool {
	return m.Size() == 0
}

func (m ComparableHashMap[K, V]) Remove(key K) {
	_, _ = m.TryRemove(key)
}

func (m ComparableHashMap[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	oldValue, oldExists := m[key]
	delete(m, key)
	return oldExists, oldValue
}

func (m ComparableHashMap[K, V]) Keys() []K {
	return maps.Keys(m)
}

func (m ComparableHashMap[K, V]) Values() []V {
	return maps.Values(m)
}

func (m ComparableHashMap[K, V]) Iter() <-chan ds.KeyValuePair[K, V] {
	ch := make(chan ds.KeyValuePair[K, V], 1)
	go func() {
		defer close(ch)
		for k, v := range m {
			ch <- ds.KeyValuePair[K, V]{
				Key:   k,
				Value: v,
			}
		}
	}()
	return ch
}

func (m ComparableHashMap[K, V]) Clone() ds.HashMap[K, V] {
	return maps.Clone(m)
}

func (m ComparableHashMap[K, V]) MarshalJSON() ([]byte, error) {
	temp := make(map[K]V)
	for k, v := range m {
		temp[k] = v
	}
	serialised, err := json.Marshal(temp)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal")
	}
	return serialised, nil
}
func (m ComparableHashMap[K, V]) UnmarshalJSON(data []byte) error {
	var temp map[K]V
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not json marshal comparable hash map")
	}
	m.Clear()
	for k, v := range temp {
		m[k] = v
	}
	return nil
}
