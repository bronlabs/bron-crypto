package hashmap

import (
	"github.com/copperexchange/krypton/pkg/base/types"
)

type HashMap[K types.Hashable, T any] struct {
	keys   map[[32]byte]types.Hashable
	values map[[32]byte]T
}

func NewHashMap[K types.Hashable, T any]() *HashMap[K, T] {
	return &HashMap[K, T]{
		keys:   make(map[[32]byte]types.Hashable),
		values: make(map[[32]byte]T),
	}
}

func (m *HashMap[K, T]) Get(key types.Hashable) (T, bool) {
	e, exists := m.values[key.Hash()]
	return e, exists
}

func (m *HashMap[K, T]) Size() int {
	return len(m.values)
}

func (m *HashMap[K, T]) IsEmpty() bool {
	return m.Size() == 0
}

func (m *HashMap[K, T]) Contains(key types.Hashable) bool {
	_, exists := m.Get(key)
	return exists
}

func (m *HashMap[K, T]) Put(key types.Hashable, value T) {
	if key == nil {
		return
	}
	keyHash := key.Hash()
	m.keys[keyHash] = key
	m.values[keyHash] = value
}

func (m *HashMap[K, T]) Remove(key types.Hashable) {
	keyHash := key.Hash()
	delete(m.keys, keyHash)
	delete(m.values, keyHash)
}

func (m *HashMap[K, T]) Clear() {
	m.values = make(map[[32]byte]T)
}

func (m *HashMap[K, T]) Keys() []K {
	keys := make([]K, 0, m.Size())
	for _, key := range m.keys {
		k, ok := key.(K)
		if ok {
			keys = append(keys, k)
		}
	}
	return keys
}

func (m *HashMap[K, T]) GetMap() map[types.Hashable]T {
	result := make(map[types.Hashable]T)
	for k, v := range m.values {
		result[m.keys[k]] = v
	}
	return result
}
