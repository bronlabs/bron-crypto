package hashmap

import (
	"bytes"
	"encoding/gob"
	"encoding/json"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type HashableHashMap[K ds.Hashable[K], V any] struct {
	inner map[uint64][]*entry[K, V]
}

type entry[K ds.Hashable[K], V any] ds.KeyValuePair[K, V]

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
	result := make([]K, m.Size())
	i := 0
	for pair := range m.Iter() {
		result[i] = pair.Key
		i++
	}
	return result
}

func (m *HashableHashMap[K, V]) Values() []V {
	result := make([]V, m.Size())
	i := 0
	for pair := range m.Iter() {
		result[i] = pair.Value
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

func (m *HashableHashMap[K, V]) Iter() <-chan ds.KeyValuePair[K, V] {
	ch := make(chan ds.KeyValuePair[K, V], 1)
	go func() {
		defer close(ch)
		for _, entries := range m.inner {
			for _, pair := range entries {
				ch <- ds.KeyValuePair[K, V]{
					Key:   pair.Key,
					Value: pair.Value,
				}
			}
		}
	}()
	return ch
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

func (m *HashableHashMap[K, V]) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(&m.inner)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "error when binary marshalling hashmap")
	}
	return buf.Bytes(), nil
}

func (m *HashableHashMap[K, V]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&m.inner)
	if err != nil {
		return errs.WrapSerialisation(err, "error when binary unmarshalling hashmap")
	}
	return nil
}
