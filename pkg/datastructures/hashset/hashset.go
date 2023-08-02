package hashset

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/types"
)

type HashSet[T types.Hashable] struct {
	value map[[32]byte]T
}

func NewHashSet[T types.Hashable](participants []T) (HashSet[T], error) {
	elements := map[[32]byte]T{}
	for i, participant := range participants {
		key := participant.Hash()
		if _, exists := elements[key]; exists {
			return HashSet[T]{}, errs.NewDuplicate("participant %d is duplicate", i)
		}
		elements[key] = participant
	}
	if len(elements) != len(participants) {
		return HashSet[T]{}, errs.NewInvalidArgument("not all participants are added")
	}
	return HashSet[T]{
		value: elements,
	}, nil
}

func (set *HashSet[T]) Get(element T) (T, bool) {
	key := element.Hash()
	e, exists := set.value[key]
	return e, exists
}

func (set *HashSet[T]) Size() int {
	return len(set.value)
}

func (set *HashSet[T]) IsEmpty() bool {
	return set.Size() == 0
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

func (set *HashSet[T]) Union(other HashSet[T]) HashSet[T] {
	result := HashSet[T]{value: make(map[[32]byte]T)}
	for _, element := range set.value {
		result.Add(element)
	}
	for _, element := range other.value {
		result.Add(element)
	}
	return result
}

func (set *HashSet[T]) Difference(other HashSet[T]) HashSet[T] {
	result := HashSet[T]{value: make(map[[32]byte]T)}
	for _, element := range set.value {
		if !other.Contains(element) {
			result.Add(element)
		}
	}
	return result
}

func (set *HashSet[T]) Intersection(other HashSet[T]) HashSet[T] {
	result := HashSet[T]{value: make(map[[32]byte]T)}
	for _, element := range set.value {
		if other.Contains(element) {
			result.Add(element)
		}
	}
	return result
}
