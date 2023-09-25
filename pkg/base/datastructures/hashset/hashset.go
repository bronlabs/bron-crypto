package hashset

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type HashSet[T types.Hashable] struct {
	value map[[32]byte]T

	_ types.Incomparable
}

func NewHashSet[T types.Hashable](participants []T) *HashSet[T] {
	elements := map[[32]byte]T{}
	for _, participant := range participants {
		key := participant.Hash()
		if _, exists := elements[key]; !exists {
			elements[key] = participant
		}
	}
	return &HashSet[T]{
		value: elements,
	}
}

func (set *HashSet[T]) Get(element T) (T, bool) {
	key := element.Hash()
	e, exists := set.value[key]
	return e, exists
}

func (set *HashSet[T]) Len() int {
	return len(set.value)
}

func (set *HashSet[T]) IsEmpty() bool {
	return set.Len() == 0
}

func (set *HashSet[T]) Contains(element T) bool {
	_, exists := set.Get(element)
	return exists
}

func (set *HashSet[T]) Add(element T) bool {
	if _, exists := set.Get(element); exists {
		return false
	}
	key := element.Hash()
	set.value[key] = element
	return true
}

func (set *HashSet[T]) Remove(element T) bool {
	if _, exists := set.Get(element); !exists {
		return false
	}
	delete(set.value, element.Hash())
	return true
}

func (set *HashSet[T]) Clear() {
	set.value = make(map[[32]byte]T)
}

func (set *HashSet[T]) Union(other *HashSet[T]) *HashSet[T] {
	result := &HashSet[T]{value: make(map[[32]byte]T)}
	for _, element := range set.value {
		result.Add(element)
	}
	for _, element := range other.value {
		result.Add(element)
	}
	return result
}

func (set *HashSet[T]) Difference(other *HashSet[T]) *HashSet[T] {
	result := &HashSet[T]{value: make(map[[32]byte]T)}
	for _, element := range set.value {
		if !other.Contains(element) {
			result.Add(element)
		}
	}
	return result
}

func (set *HashSet[T]) SymmetricDifference(other *HashSet[T]) *HashSet[T] {
	result := &HashSet[T]{value: make(map[[32]byte]T)}
	for _, element := range set.value {
		if !other.Contains(element) {
			result.Add(element)
		}
	}
	for _, element := range other.value {
		if !set.Contains(element) {
			result.Add(element)
		}
	}
	return result
}

func (set *HashSet[T]) Intersection(other *HashSet[T]) *HashSet[T] {
	result := &HashSet[T]{value: make(map[[32]byte]T)}
	for _, element := range set.value {
		if other.Contains(element) {
			result.Add(element)
		}
	}
	return result
}

func (set *HashSet[T]) Iter() map[[32]byte]T {
	return set.value
}

func (set *HashSet[T]) Clone() *HashSet[T] {
	return &HashSet[T]{value: set.Iter()}
}

func (set *HashSet[T]) List() []T {
	result := make([]T, len(set.value))
	i := -1
	for _, element := range set.value {
		i++
		result[i] = element
	}
	return result
}

func (set *HashSet[T]) Equals(other *HashSet[T]) bool {
	if set.Len() != other.Len() {
		return false
	}
	for _, element := range set.value {
		if !other.Contains(element) {
			return false
		}
	}
	return true
}
