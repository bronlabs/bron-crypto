package hashmap

import (
	"encoding/json"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type HashableHashMap[K ds.Hashable[K], V any] struct {
	inner map[uint64][]*entry[K, V]
}

type entry[K ds.Hashable[K], V any] ds.MapEntry[K, V]

func NewHashableHashMap[K ds.Hashable[K], V any]() ds.Map[K, V] {
	return &HashableHashMap[K, V]{
		inner: make(map[uint64][]*entry[K, V]),
	}
}

func (m *HashableHashMap[K, V]) Get(key K) (value V, exists bool) {
	var nilValue V

	hashCode := key.HashCode()
	values, ok := m.inner[hashCode]
	if !ok {
		return nilValue, false
	}
	for _, e := range values {
		if e.Key.Equal(key) {
			return e.Value, true
		}
	}

	return nilValue, false
}

func (m *HashableHashMap[K, V]) Retain(keys ds.Set[K]) ds.Map[K, V] {
	return m.Filter(keys.Contains)
}

func (m *HashableHashMap[K, V]) Filter(predicate func(key K) bool) ds.Map[K, V] {
	result := NewHashableHashMap[K, V]()
	for _, entries := range m.inner {
		for _, e := range entries {
			if predicate(e.Key) {
				result.Put(e.Key, e.Value)
			}
		}
	}
	return result
}

func (m *HashableHashMap[K, V]) ContainsKey(key K) bool {
	for _, e := range m.inner[key.HashCode()] {
		if key.Equal(e.Key) {
			return true
		}
	}
	return false
}

func (m *HashableHashMap[K, V]) Put(key K, value V) {
	_, _ = m.TryPut(key, value)
}

func (m *HashableHashMap[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	var nilValue V

	hashCode := key.HashCode()
	entries, ok := m.inner[hashCode]
	if !ok {
		m.inner[hashCode] = []*entry[K, V]{
			{
				Key:   key,
				Value: newValue,
			},
		}
		return false, nilValue
	}

	for _, v := range entries {
		if v.Key.Equal(key) {
			oldValue := v.Value
			v.Value = newValue
			return true, oldValue
		}
	}

	m.inner[hashCode] = append(m.inner[hashCode], &entry[K, V]{
		Key:   key,
		Value: newValue,
	})
	return false, nilValue
}

func (m *HashableHashMap[K, V]) Clear() {
	m.inner = make(map[uint64][]*entry[K, V])
}

func (m *HashableHashMap[K, V]) IsEmpty() bool {
	return len(m.inner) == 0
}

func (m *HashableHashMap[K, V]) Size() int {
	size := 0
	for _, v := range m.inner {
		size += len(v)
	}
	return size
}

func (m *HashableHashMap[K, V]) Remove(key K) {
	_, _ = m.TryRemove(key)
}

func (m *HashableHashMap[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	var nilValue V

	entries, ok := m.inner[key.HashCode()]
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
		delete(m.inner, key.HashCode())
	} else {
		m.inner[key.HashCode()] = newEntries
	}
	return true, removedValue
}

func (m *HashableHashMap[K, V]) Keys() []K {
	var keys []K
	for _, entries := range m.inner {
		for _, entry := range entries {
			keys = append(keys, entry.Key)
		}
	}
	return keys
}

func (m *HashableHashMap[K, V]) Values() []V {
	result := make([]V, m.Size())
	i := 0

	for iterator := m.Iterator(); iterator.HasNext(); {
		value := iterator.Next()
		result[i] = value.Value
		i++
	}

	return result
}

func (m *HashableHashMap[K, V]) Clone() ds.Map[K, V] {
	result := NewHashableHashMap[K, V]().(*HashableHashMap[K, V]) //nolint:errcheck,forcetypeassert // trivial
	for code, entries := range m.inner {
		result.inner[code] = make([]*entry[K, V], len(entries))
		for i, e := range entries {
			result.inner[code][i] = &entry[K, V]{
				Key:   e.Key,
				Value: e.Value,
			}
		}
	}
	return result
}

func (m *HashableHashMap[K, V]) Iterator() ds.Iterator[ds.MapEntry[K, V]] {
	return &hashableHashMapIterator[K, V]{
		nextKeyIndex: 0,
		keys:         m.Keys(),
		Hashable:     m,
	}
}

func (m *HashableHashMap[K, V]) MarshalJSON() ([]byte, error) {
	serialised, err := json.Marshal(m.inner)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal")
	}
	return serialised, nil
}

func (m *HashableHashMap[K, V]) UnmarshalJSON(data []byte) error {
	var temp map[uint64][]*entry[K, V]
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal hashable hashmap")
	}
	m.inner = temp
	return nil
}

type hashableHashMapIterator[K ds.Hashable[K], V any] struct {
	nextKeyIndex int
	keys         []K
	Hashable     *HashableHashMap[K, V]
}

func (i *hashableHashMapIterator[K, V]) Next() ds.MapEntry[K, V] {
	if i.nextKeyIndex >= len(i.keys) {
		panic("index out of range")
	}
	key := i.keys[i.nextKeyIndex]
	value, _ := i.Hashable.Get(key)
	i.nextKeyIndex++
	return ds.MapEntry[K, V]{Key: key, Value: value}
}

func (i *hashableHashMapIterator[K, V]) HasNext() bool {
	return i.nextKeyIndex < len(i.keys)
}
