package newHashmap

type Hashable[K any] interface {
	HashCode() uint64
	Equals(rhs K) bool
}

type hashableHashMap[K Hashable[K], V any] struct {
	inner map[uint64][]*entry[K, V]
}

type entry[K Hashable[K], V any] struct {
	key   K
	value V
}

func NewHashableHashMap[K Hashable[K], V any]() HashMap[K, V] {
	return &hashableHashMap[K, V]{
		inner: make(map[uint64][]*entry[K, V]),
	}
}

func (m *hashableHashMap[K, V]) Get(key K) (value V, exists bool) {
	var nilValue V

	hashCode := key.HashCode()
	values, ok := m.inner[hashCode]
	if !ok {
		return nilValue, false
	}
	for _, e := range values {
		if e.key.Equals(key) {
			return e.value, true
		}
	}

	return nilValue, false
}

func (m *hashableHashMap[K, V]) Put(key K, newValue V) (replaced bool, oldValue V) {
	var nilValue V

	hashCode := key.HashCode()
	entries, ok := m.inner[hashCode]
	if !ok {
		m.inner[hashCode] = []*entry[K, V]{
			{
				key:   key,
				value: newValue,
			},
		}
		return false, nilValue
	}

	for _, v := range entries {
		if v.key.Equals(key) {
			oldValue := v.value
			v.value = newValue
			return true, oldValue
		}
	}

	m.inner[hashCode] = append(m.inner[hashCode], &entry[K, V]{
		key:   key,
		value: newValue,
	})
	return false, nilValue
}

func (m *hashableHashMap[K, V]) Clear() {
	m.inner = make(map[uint64][]*entry[K, V])
}

func (m *hashableHashMap[K, V]) IsEmpty() bool {
	return len(m.inner) == 0
}

func (m *hashableHashMap[K, V]) Size() int {
	size := 0
	for _, v := range m.inner {
		size += len(v)
	}
	return size
}

func (m *hashableHashMap[K, V]) ContainsKey(key K) bool {
	for _, e := range m.inner[key.HashCode()] {
		if key.Equals(e.key) {
			return true
		}
	}

	return false
}

func (m *hashableHashMap[K, V]) Remove(key K) (removed bool, removedValue V) {
	var nilValue V

	entries, ok := m.inner[key.HashCode()]
	if !ok {
		return false, nilValue
	}

	idx := -1
	for i, e := range entries {
		if e.key.Equals(key) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return false, nilValue
	}

	removedValue = entries[idx].value
	entries[idx] = entries[len(entries)-1]
	newEntries := entries[:len(entries)-1]
	if len(newEntries) == 0 {
		delete(m.inner, key.HashCode())
	} else {
		m.inner[key.HashCode()] = newEntries
	}

	return true, removedValue
}
