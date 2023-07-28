package hashmap

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/comparableelement"
)

type HashMap[T comparableelement.Hashable] struct {
	elements map[string]T
}

func NewHashmap[T comparableelement.Hashable](participants []T) (HashMap[T], error) {
	elements := map[string]T{}
	for i, participant := range participants {
		// TODO: we can't check generic is nil at the moment unless we use reflection. Hopefully in future Go update we can do tht
		//if participant == nil {
		//	return nil, errs.NewIsNil("participant %d is nil", i)
		//}
		if _, exists := elements[participant.HashCode()]; exists {
			return HashMap[T]{}, errs.NewDuplicate("participant %d is duplicate", i)
		}
		elements[participant.HashCode()] = participant
	}
	if len(elements) != len(participants) {
		return HashMap[T]{}, errs.NewInvalidArgument("not all participants are added")
	}
	return HashMap[T]{
		elements: elements,
	}, nil
}

func Get[T comparableelement.Hashable](set HashMap[T], element T) (T, bool) {
	e, exists := set.elements[element.HashCode()]
	return e, exists
}

func Size[T comparableelement.Hashable](set HashMap[T]) int {
	return len(set.elements)
}

func IsEmpty[T comparableelement.Hashable](set HashMap[T]) bool {
	return Size(set) == 0
}

func Contains[T comparableelement.Hashable](set HashMap[T], element T) bool {
	_, exists := Get(set, element)
	return exists
}

// Put or override element if exists
func Put[T comparableelement.Hashable](set HashMap[T], element T) HashMap[T] {
	if _, exists := Get(set, element); !exists {
		set.elements[element.HashCode()] = element
	}
	return set
}

// similar to put but will return error if element already exists
func Add[T comparableelement.Hashable](set HashMap[T], element T) (HashMap[T], error) {
	if _, exists := Get(set, element); exists {
		return HashMap[T]{}, errs.NewDuplicate("element already exists")
	}
	set.elements[element.HashCode()] = element
	return set, nil
}
