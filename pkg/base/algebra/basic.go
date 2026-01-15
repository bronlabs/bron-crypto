package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

type (
	Element[E any]         = crtp.Element[E]
	Structure[E any]       = crtp.Structure[E]
	FiniteStructure[E any] = crtp.FiniteStructure[E]
	Quotient[E, M, A any]  = crtp.Quotient[E, M, A]
	Residue[E, M any]      = crtp.Residue[E, M]
)

func StructureIs[S crtp.Structure[E], E any](s Structure[E]) bool {
	_, ok := s.(S)
	return ok
}

func StructureAs[S crtp.Structure[E], E any](s Structure[E]) (S, error) {
	out, ok := s.(S)
	if !ok {
		return *new(S), errs2.New("structure does not implement the expected type")
	}
	return out, nil
}

func StructureMustBeAs[S crtp.Structure[E], E any](s Structure[E]) S {
	out, err := StructureAs[S](s)
	if err != nil {
		panic(err)
	}
	return out
}
