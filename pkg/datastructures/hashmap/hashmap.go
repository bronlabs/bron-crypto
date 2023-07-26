package hashmap

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/comparableelement"
)

type HashMap[T comparableelement.ComparableElement] interface {
	getElements() map[string]T
}

func Get[T comparableelement.ComparableElement](set HashMap[T], element T) (T, bool) {
	e, exists := set.getElements()[element.HashCode()]
	return e, exists
}

func Size[T comparableelement.ComparableElement](set HashMap[T]) int {
	return len(set.getElements())
}

func IsEmpty[T comparableelement.ComparableElement](set HashMap[T]) bool {
	return Size(set) == 0
}

func Contains[T comparableelement.ComparableElement](set HashMap[T], element T) bool {
	_, exists := Get(set, element)
	return exists
}

// Put or override element if exists
func Put[T comparableelement.ComparableElement](set HashMap[T], element T) HashMap[T] {
	if _, exists := Get(set, element); !exists {
		set.getElements()[element.HashCode()] = element
	}
	return set
}

// similar to put but will return error if element already exists
func Add[T comparableelement.ComparableElement](set HashMap[T], element T) (HashMap[T], error) {
	if _, exists := Get(set, element); exists {
		return nil, errs.NewDuplicate("element already exists")
	}
	set.getElements()[element.HashCode()] = element
	return set, nil
}
