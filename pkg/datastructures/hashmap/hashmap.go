package hashmap

import (
	"encoding/hex"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
)

type HashMap[T Hashable] struct {
	elements map[string]T
}

type Hashable interface {
	HashCode() [32]byte
}

func Equals(a Hashable, b Hashable) bool {
	return a.HashCode() == b.HashCode()
}

func NewHashmap[T Hashable](participants []T) (HashMap[T], error) {
	elements := map[string]T{}
	for i, participant := range participants {
		// TODO: we can't check generic is nil at the moment unless we use reflection. Hopefully in future Go update we can do tht
		//if participant == nil {
		//	return nil, errs.NewIsNil("participant %d is nil", i)
		//}
		keyBytes := participant.HashCode()
		key := hex.EncodeToString(keyBytes[:])
		if _, exists := elements[key]; exists {
			return HashMap[T]{}, errs.NewDuplicate("participant %d is duplicate", i)
		}
		elements[key] = participant
	}
	if len(elements) != len(participants) {
		return HashMap[T]{}, errs.NewInvalidArgument("not all participants are added")
	}
	return HashMap[T]{
		elements: elements,
	}, nil
}

func Get[T Hashable](set HashMap[T], element T) (T, bool) {
	keyBytes := element.HashCode()
	key := hex.EncodeToString(keyBytes[:])
	e, exists := set.elements[key]
	return e, exists
}

func Size[T Hashable](set HashMap[T]) int {
	return len(set.elements)
}

func IsEmpty[T Hashable](set HashMap[T]) bool {
	return Size(set) == 0
}

func Contains[T Hashable](set HashMap[T], element T) bool {
	_, exists := Get(set, element)
	return exists
}

// Put or override element if exists
func Put[T Hashable](set HashMap[T], element T) HashMap[T] {
	if _, exists := Get(set, element); !exists {
		keyBytes := element.HashCode()
		key := hex.EncodeToString(keyBytes[:])
		set.elements[key] = element
	}
	return set
}

// similar to put but will return error if element already exists
func Add[T Hashable](set HashMap[T], element T) (HashMap[T], error) {
	if _, exists := Get(set, element); exists {
		return HashMap[T]{}, errs.NewDuplicate("element already exists")
	}
	keyBytes := element.HashCode()
	key := hex.EncodeToString(keyBytes[:])
	set.elements[key] = element
	return set, nil
}
