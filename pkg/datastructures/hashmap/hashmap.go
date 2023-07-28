package hashmap

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/types"
)

type HashMap[K types.Hashable, T any] struct {
	value map[[32]byte]T
}

func NewHashMap[K types.Hashable, T any]() HashMap[K, T] {
	return HashMap[K, T]{
		value: make(map[[32]byte]T),
	}
}

func (set *HashMap[K, T]) Get(key types.Hashable) (T, bool) {
	e, exists := set.value[key.Hash()]
	return e, exists
}

func (set *HashMap[K, T]) Size() int {
	return len(set.value)
}

func (set *HashMap[K, T]) IsEmpty() bool {
	return set.Size() == 0
}

func (set *HashMap[K, T]) Contains(key types.Hashable) bool {
	_, exists := set.Get(key)
	return exists
}

func (set *HashMap[K, T]) Put(key types.Hashable, value T) {
	if key == nil {
		return
	}
	set.value[key.Hash()] = value
}
