package hashmap

import (
	"encoding/json"
	"iter"
	"sync"

	"golang.org/x/exp/maps"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type NativeMap[K comparable, V, T any] map[K]V

func (m NativeMap[K, V, T]) Get(key K) (value V, exists bool) {
	v, exists := m[key]
	return v, exists
}

func (m NativeMap[K, V, T]) Retain(keys ...K) T {
	return m.Filter(func(key K) bool {
		for _, k := range keys {
			if k == key {
				return true
			}
		}
		return false
	})
}

func (m NativeMap[K, V, T]) Filter(predicate func(key K) bool) T {
	result := make(NativeMap[K, V, T])
	for k, v := range m {
		if predicate(k) {
			result[k] = v
		}
	}
	return any(result).(T)
}

func (m NativeMap[K, V, T]) ContainsKey(key K) bool {
	_, exists := m.Get(key)
	return exists
}

func (m NativeMap[K, V, T]) Put(key K, value V) {
	_, _ = m.TryPut(key, value)
}

func (m NativeMap[K, V, T]) TryPut(key K, newValue V) (replaced bool, oldValue V) {
	oldV, oldExists := m[key]
	m[key] = newValue
	return oldExists, oldV
}

func (m NativeMap[K, V, T]) Clear() {
	clear(m)
}

func (m NativeMap[K, V, T]) Size() int {
	return len(m)
}

func (m NativeMap[K, V, T]) IsEmpty() bool {
	return len(m) == 0
}

func (m NativeMap[K, V, T]) Remove(key K) {
	_, _ = m.TryRemove(key)
}

func (m NativeMap[K, V, T]) TryRemove(key K) (removed bool, removedValue V) {
	oldValue, oldExists := m[key]
	delete(m, key)
	return oldExists, oldValue
}

func (m NativeMap[K, V, T]) Keys() []K {
	return maps.Keys(m)
}

func (m NativeMap[K, V, T]) Values() []V {
	return maps.Values(m)
}

func (m NativeMap[K, V, T]) Iter() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for k, v := range m {
			if !yield(k, v) {
				return
			}
		}
	}
}

func (m NativeMap[K, V, T]) Enumerate() iter.Seq2[int, ds.MapEntry[K, V]] {
	return func(yield func(int, ds.MapEntry[K, V]) bool) {
		i := 0
		for k, v := range m {
			if !yield(i, ds.MapEntry[K, V]{Key: k, Value: v}) {
				return
			}
			i++
		}
	}
}

// Immutable
type ImmutableComparableHashMap[K comparable, V any] struct {
	inner NativeMap[K, V, ds.Map[K, V]]
}

func NewImmutableComparable[K comparable, V any](xs ...ds.MapEntry[K, V]) ds.Map[K, V] {
	out := make(NativeMap[K, V, ds.Map[K, V]])
	for _, entry := range xs {
		out[entry.Key] = entry.Value
	}
	return &ImmutableComparableHashMap[K, V]{inner: out}
}

func NewImmutableComparableFromNativeLike[K comparable, V any, T ~map[K]V](arg T) ds.Map[K, V] {
	out := make(NativeMap[K, V, ds.Map[K, V]])
	if arg != nil {
		maps.Copy(out, arg)
	}
	return &ImmutableComparableHashMap[K, V]{inner: out}
}

func CollectToImmutableComparable[K comparable, V any](xs []K, ys []V) (ds.Map[K, V], error) {
	if len(xs) == 0 && len(ys) == 0 {
		return &ImmutableComparableHashMap[K, V]{inner: make(NativeMap[K, V, ds.Map[K, V]])}, nil
	}
	if len(xs) != len(ys) {
		return nil, errs.NewArgument("xs and ys must have the same length")
	}
	out := make(NativeMap[K, V, ds.Map[K, V]])
	for i, x := range xs {
		out[x] = ys[i]
	}
	return &ImmutableComparableHashMap[K, V]{inner: out}, nil
}

func (m ImmutableComparableHashMap[K, V]) IsImmutable() bool {
	return true
}

func (m ImmutableComparableHashMap[K, V]) Unfreeze() ds.MutableMap[K, V] {
	return NewComparableFromNativeLike(m.inner)
}

func (m ImmutableComparableHashMap[K, V]) Get(key K) (value V, exists bool) {
	return m.inner.Get(key)
}

func (m ImmutableComparableHashMap[K, V]) Retain(keys ...K) ds.Map[K, V] {
	return m.inner.Retain(keys...)
}

func (m ImmutableComparableHashMap[K, V]) Filter(predicate func(key K) bool) ds.Map[K, V] {
	return m.inner.Filter(predicate)
}

func (m ImmutableComparableHashMap[K, V]) ContainsKey(key K) bool {
	return m.inner.ContainsKey(key)
}

func (m ImmutableComparableHashMap[K, V]) IsEmpty() bool {
	return m.Size() == 0
}

func (m ImmutableComparableHashMap[K, V]) Size() int {
	return m.inner.Size()
}
func (m ImmutableComparableHashMap[K, V]) Keys() []K {
	return m.inner.Keys()
}
func (m ImmutableComparableHashMap[K, V]) Values() []V {
	return m.inner.Values()
}
func (m ImmutableComparableHashMap[K, V]) Clone() ds.Map[K, V] {
	return NewImmutableComparableFromNativeLike(m.inner)
}

func (m ImmutableComparableHashMap[K, V]) MarshalJSON() ([]byte, error) {
	serialised, err := json.Marshal(m.inner)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal comparable immutable hash map")
	}
	return serialised, nil
}

func (m *ImmutableComparableHashMap[K, V]) UnmarshalJSON(data []byte) error {
	var temp map[K]V
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not json marshal comparable immutable hash map")
	}
	m.inner = temp
	return nil
}

func (m ImmutableComparableHashMap[K, V]) Iter() iter.Seq2[K, V] {
	return m.inner.Iter()
}

func (m ImmutableComparableHashMap[K, V]) Enumerate() iter.Seq2[int, ds.MapEntry[K, V]] {
	return m.inner.Enumerate()
}

func NewComparable[K comparable, V any](xs ...ds.MapEntry[K, V]) ds.MutableMap[K, V] {
	out := make(NativeMap[K, V, ds.MutableMap[K, V]])
	for _, entry := range xs {
		out[entry.Key] = entry.Value
	}
	return &ComparableHashMap[K, V]{NativeMap[K, V, ds.MutableMap[K, V]](out)}
}

func CollectToComparable[K comparable, V any](xs []K, ys []V) (ds.MutableMap[K, V], error) {
	if len(xs) == 0 && len(ys) == 0 {
		return &ComparableHashMap[K, V]{NativeMap[K, V, ds.MutableMap[K, V]](make(NativeMap[K, V, ds.MutableMap[K, V]]))}, nil
	}
	if len(xs) != len(ys) {
		return nil, errs.NewArgument("xs and ys must have the same length")
	}
	out := make(NativeMap[K, V, ds.MutableMap[K, V]])
	for i, x := range xs {
		out[x] = ys[i]
	}
	return &ComparableHashMap[K, V]{NativeMap[K, V, ds.MutableMap[K, V]](out)}, nil
}

func NewComparableFromNativeLike[K comparable, V any, T ~map[K]V](arg T) ds.MutableMap[K, V] {
	out := make(NativeMap[K, V, ds.MutableMap[K, V]])
	if arg == nil {
		return &ComparableHashMap[K, V]{NativeMap[K, V, ds.MutableMap[K, V]](out)}
	}
	maps.Copy(out, arg)
	return &ComparableHashMap[K, V]{NativeMap[K, V, ds.MutableMap[K, V]](out)}
}

type ComparableHashMap[K comparable, V any] struct {
	NativeMap[K, V, ds.MutableMap[K, V]]
}

func (m ComparableHashMap[K, V]) IsImmutable() bool {
	return false
}

func (m ComparableHashMap[K, V]) Freeze() ds.Map[K, V] {
	return &ImmutableComparableHashMap[K, V]{
		inner: NativeMap[K, V, ds.Map[K, V]](maps.Clone(m.NativeMap)),
	}
}

func (m ComparableHashMap[K, V]) ThreadSafe() ds.ConcurrentMap[K, V] {
	return &ConcurrentMap[K, V]{
		inner: NewComparableFromNativeLike(m.NativeMap),
		mu:    sync.RWMutex{},
	}
}

func (m ComparableHashMap[K, V]) Clone() ds.MutableMap[K, V] {
	return any(maps.Clone(m.NativeMap)).(ds.MutableMap[K, V])
}

func (m ComparableHashMap[K, V]) MarshalJSON() ([]byte, error) {
	serialised, err := json.Marshal(m)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal")
	}
	return serialised, nil
}
func (m *ComparableHashMap[K, V]) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &m.NativeMap); err != nil {
		return errs.WrapSerialisation(err, "could not json marshal comparable hash map")
	}
	return nil
}
