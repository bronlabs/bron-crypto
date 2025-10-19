package hashmap

import (
	"encoding/json"
	"iter"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type HashableEntry[K base.Hashable[K], V any] ds.MapEntry[K, V]

type HashableMapping[K base.Hashable[K], V any] map[base.HashCode][]*HashableEntry[K, V]

func (m HashableMapping[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	hashCode := key.HashCode()
	entries, exists := m[hashCode]
	if !exists {
		m[hashCode] = []*HashableEntry[K, V]{
			{
				Key:   key,
				Value: newValue,
			},
		}
		return false, *new(V)
	}

	for _, v := range entries {
		if v.Key.Equal(key) {
			oldValue := v.Value
			v.Value = newValue
			return true, oldValue
		}
	}

	m[hashCode] = append(m[hashCode], &HashableEntry[K, V]{
		Key:   key,
		Value: newValue,
	})
	return false, *new(V)
}
func (m HashableMapping[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	var nilValue V

	entries, ok := m[key.HashCode()]
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
		delete(m, key.HashCode())
	} else {
		m[key.HashCode()] = newEntries
	}
	return true, removedValue
}

type HashMapTrait[K base.Hashable[K], V, T any] struct {
	inner HashableMapping[K, V]
}

func (m HashMapTrait[K, V, _]) IsHashable() bool {
	return true
}

func (m HashMapTrait[K, V, _]) Get(key K) (value V, exists bool) {
	hashCode := key.HashCode()
	values, ok := m.inner[hashCode]
	if !ok {
		return *new(V), false
	}
	for _, e := range values {
		if e.Key.Equal(key) {
			return e.Value, true
		}
	}

	return *new(V), false
}

func (m HashMapTrait[K, V, T]) Retain(keys ...K) T {
	return m.Filter(func(key K) bool {
		for _, k := range keys {
			if k.Equal(key) {
				return true
			}
		}
		return false
	})
}

func (m HashMapTrait[K, V, T]) Filter(predicate func(key K) bool) T {
	inner := make(HashableMapping[K, V])
	for _, entries := range m.inner {
		for _, e := range entries {
			if predicate(e.Key) {
				inner.TryPut(e.Key, e.Value)
			}
		}
	}
	result := HashMapTrait[K, V, T]{
		inner: inner,
	}
	out, ok := any(result).(T)
	if !ok {
		panic("could not convert filtered map to target type")
	}
	return out
}

func (m HashMapTrait[K, V, _]) ContainsKey(key K) bool {
	for _, e := range m.inner[key.HashCode()] {
		if key.Equal(e.Key) {
			return true
		}
	}
	return false
}

func (m HashMapTrait[K, V, _]) IsEmpty() bool {
	return len(m.inner) == 0
}

func (m HashMapTrait[K, V, _]) Size() int {
	size := 0
	for _, v := range m.inner {
		size += len(v)
	}
	return size
}

func (m HashMapTrait[K, V, _]) Keys() []K {
	var keys []K
	for _, entries := range m.inner {
		for _, entry := range entries {
			keys = append(keys, entry.Key)
		}
	}
	return keys
}

func (m HashMapTrait[K, V, _]) Values() []V {
	result := make([]V, 0)
	for _, value := range m.Iter() {
		result = append(result, value)
	}
	return result
}

func (m HashMapTrait[K, V, _]) Iter() iter.Seq2[K, V] {
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

func (m HashMapTrait[K, V, _]) Enumerate() iter.Seq2[int, ds.MapEntry[K, V]] {
	return func(yield func(int, ds.MapEntry[K, V]) bool) {
		i := 0
		for key, value := range m.Iter() {
			if !yield(i, ds.MapEntry[K, V]{Key: key, Value: value}) {
				return
			}
			i++
		}
	}
}

func NewImmutableHashable[K base.Hashable[K], V any]() ds.Map[K, V] {
	return &ImmutableHashableHashMap[K, V]{
		HashMapTrait[K, V, ds.Map[K, V]]{
			inner: make(HashableMapping[K, V]),
		},
	}
}

func CollectToImmutableHashable[K base.Hashable[K], V any](xs []K, ys []V) (ds.Map[K, V], error) {
	m, err := CollectToHashable(xs, ys)
	if err != nil {
		return nil, err
	}
	return m.Freeze(), nil
}

type ImmutableHashableHashMap[K base.Hashable[K], V any] struct {
	HashMapTrait[K, V, ds.Map[K, V]]
}

func (m ImmutableHashableHashMap[K, V]) IsImmutable() bool {
	return true
}

func (m ImmutableHashableHashMap[K, V]) IsSubMap(other ds.Map[K, V], eq func(a, b V) bool) bool {
	if other == nil {
		return false
	}
	if m.Size() > other.Size() {
		return false
	}
	return sliceutils.All(m.Keys(), func(k K) bool {
		v1, _ := m.Get(k)
		v2, exists := other.Get(k)
		return exists && eq(v1, v2)
	})
}

func (m ImmutableHashableHashMap[K, V]) IsProperSubMap(other ds.Map[K, V], eq func(a, b V) bool) bool {
	return m.Size() < other.Size() && m.IsSubMap(other, eq)
}

func (m ImmutableHashableHashMap[K, V]) IsSuperMap(other ds.Map[K, V], eq func(a, b V) bool) bool {
	return other.IsSubMap(m, eq)
}

func (m ImmutableHashableHashMap[K, V]) IsProperSuperMap(other ds.Map[K, V], eq func(a, b V) bool) bool {
	return other.IsProperSubMap(m, eq)
}

func (m ImmutableHashableHashMap[K, V]) Unfreeze() ds.MutableMap[K, V] {
	return &MutableHashableHashMap[K, V]{
		HashMapTrait[K, V, ds.MutableMap[K, V]]{
			inner: m.inner,
		},
	}
}

func (m ImmutableHashableHashMap[K, V]) Clone() ds.Map[K, V] {
	inner := make(HashableMapping[K, V])
	for code, entries := range m.inner {
		inner[code] = make([]*HashableEntry[K, V], len(entries))
		for i, e := range entries {
			inner[code][i] = &HashableEntry[K, V]{
				Key:   e.Key,
				Value: e.Value,
			}
		}
	}
	return &ImmutableHashableHashMap[K, V]{
		HashMapTrait[K, V, ds.Map[K, V]]{
			inner: inner,
		},
	}
}

func (m ImmutableHashableHashMap[K, V]) MarshalJSON() ([]byte, error) {
	serialised, err := json.Marshal(m.inner)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal")
	}
	return serialised, nil
}

func (m *ImmutableHashableHashMap[K, V]) UnmarshalJSON(data []byte) error {
	var temp HashableMapping[K, V]
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal hashable hashmap")
	}
	m.HashMapTrait = HashMapTrait[K, V, ds.Map[K, V]]{
		inner: temp,
	}
	return nil
}

func NewHashable[K base.Hashable[K], V any]() ds.MutableMap[K, V] {
	return &MutableHashableHashMap[K, V]{
		HashMapTrait[K, V, ds.MutableMap[K, V]]{
			inner: make(HashableMapping[K, V]),
		},
	}
}

func CollectToHashable[K base.Hashable[K], V any](xs []K, ys []V) (ds.MutableMap[K, V], error) {
	if len(xs) != len(ys) {
		return nil, errs.NewArgument("xs and ys must have the same length")
	}
	m := NewHashable[K, V]()
	for i := range xs {
		m.Put(xs[i], ys[i])
	}
	return m, nil
}

type MutableHashableHashMap[K base.Hashable[K], V any] struct {
	HashMapTrait[K, V, ds.MutableMap[K, V]]
}

func (m MutableHashableHashMap[K, V]) IsImmutable() bool {
	return false
}

func (m MutableHashableHashMap[K, V]) IsSubMap(other ds.MutableMap[K, V], eq func(a, b V) bool) bool {
	if other == nil {
		return false
	}
	if m.Size() > other.Size() {
		return false
	}
	return sliceutils.All(m.Keys(), func(k K) bool {
		v1, _ := m.Get(k)
		v2, exists := other.Get(k)
		return exists && eq(v1, v2)
	})
}

func (m MutableHashableHashMap[K, V]) IsProperSubMap(other ds.MutableMap[K, V], eq func(a, b V) bool) bool {
	return m.Size() < other.Size() && m.IsSubMap(other, eq)
}
func (m MutableHashableHashMap[K, V]) IsSuperMap(other ds.MutableMap[K, V], eq func(a, b V) bool) bool {
	return other.IsSubMap(m, eq)
}
func (m MutableHashableHashMap[K, V]) IsProperSuperMap(other ds.MutableMap[K, V], eq func(a, b V) bool) bool {
	return other.IsProperSubMap(m, eq)
}

func (m MutableHashableHashMap[K, V]) Freeze() ds.Map[K, V] {
	return &ImmutableHashableHashMap[K, V]{
		HashMapTrait[K, V, ds.Map[K, V]]{
			inner: m.inner,
		},
	}
}

func (m MutableHashableHashMap[K, V]) ThreadSafe() ds.ConcurrentMap[K, V] {
	return &ConcurrentMap[K, V]{
		inner: m.Clone(),
		mu:    sync.RWMutex{},
	}
}

func (m MutableHashableHashMap[K, V]) Clone() ds.MutableMap[K, V] {
	inner := make(HashableMapping[K, V])
	for code, entries := range m.inner {
		inner[code] = make([]*HashableEntry[K, V], len(entries))
		for i, e := range entries {
			inner[code][i] = &HashableEntry[K, V]{
				Key:   e.Key,
				Value: e.Value,
			}
		}
	}
	return &MutableHashableHashMap[K, V]{
		HashMapTrait[K, V, ds.MutableMap[K, V]]{
			inner: inner,
		},
	}
}

func (m MutableHashableHashMap[K, V]) MarshalJSON() ([]byte, error) {
	serialised, err := json.Marshal(m.inner)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal")
	}
	return serialised, nil
}

func (m *MutableHashableHashMap[K, V]) UnmarshalJSON(data []byte) error {
	var temp HashableMapping[K, V]
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal hashable hashmap")
	}
	m.HashMapTrait = HashMapTrait[K, V, ds.MutableMap[K, V]]{
		inner: temp,
	}
	return nil
}

func (m MutableHashableHashMap[K, V]) Put(key K, value V) {
	_, _ = m.TryPut(key, value)
}

func (m MutableHashableHashMap[K, V]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	return m.inner.TryPut(key, newValue)
}

func (m MutableHashableHashMap[K, V]) Clear() {
	m.inner = make(HashableMapping[K, V])
}

func (m MutableHashableHashMap[K, V]) Remove(key K) {
	_, _ = m.TryRemove(key)
}

func (m MutableHashableHashMap[K, V]) TryRemove(key K) (removed bool, removedValue V) {
	return m.inner.TryRemove(key)
}
