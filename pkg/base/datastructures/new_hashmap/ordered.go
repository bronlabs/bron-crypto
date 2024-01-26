package newHashmap

import "golang.org/x/exp/constraints"

type orderedHashMap[K constraints.Ordered, V any] struct {
	inner map[K]V
}

func NewOrderedHashMap[K constraints.Ordered, V any]() HashMap[K, V] {
	return &orderedHashMap[K, V]{
		inner: make(map[K]V),
	}
}

func (m *orderedHashMap[K, V]) Get(key K) (value V, exists bool) {
	v, e := m.inner[key]
	return v, e
}

func (m *orderedHashMap[K, V]) Put(key K, newValue V) (replaced bool, oldValue V) {
	oldV, oldE := m.inner[key]
	m.inner[key] = newValue
	return oldE, oldV
}

func (m *orderedHashMap[K, V]) Clear() {
	m.inner = make(map[K]V)
}

func (m *orderedHashMap[K, V]) IsEmpty() bool {
	return len(m.inner) == 0
}

func (m *orderedHashMap[K, V]) Size() int {
	return len(m.inner)
}

func (m *orderedHashMap[K, V]) ContainsKey(key K) bool {
	_, e := m.inner[key]
	return e
}

func (m *orderedHashMap[K, V]) Remove(key K) (removed bool, removedValue V) {
	oldV, oldE := m.inner[key]
	delete(m.inner, key)

	return oldE, oldV
}
