package hashmap

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/comparableelement"
)

type Hashmap[T comparableelement.ComparableElement] struct {
	elements map[string]T
}

func (p Hashmap[T]) getElements() map[string]T {
	return p.elements
}

func NewHashmap[T comparableelement.ComparableElement](participants []T) (HashMap[T], error) {
	elements := map[string]T{}
	for i, participant := range participants {
		// TODO: we can't check generic is nil at the moment unless we use reflection. Hopefully in future Go update we can do tht
		//if participant == nil {
		//	return nil, errs.NewIsNil("participant %d is nil", i)
		//}
		if _, exists := elements[participant.HashCode()]; exists {
			return nil, errs.NewDuplicate("participant %d is duplicate", i)
		}
		elements[participant.HashCode()] = participant
	}
	if len(elements) != len(participants) {
		return nil, errs.NewInvalidArgument("not all participants are added")
	}
	return Hashmap[T]{
		elements: elements,
	}, nil
}
