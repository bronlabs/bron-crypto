package algebra

import (
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type (
	Element[E any]             = aimpl.Element[E]
	Structure[E any]           = aimpl.Structure[E]
	FiniteStructure[E any]     = aimpl.FiniteStructure[E]
	NAry[C any]                = aimpl.NAry[C]
	Mapping[F, C any]          = aimpl.Mapping[F, C]
	Product[P, C any]          = aimpl.Product[P, C]
	CoProduct[P, C any]        = aimpl.CoProduct[P, C]
	Power[P, C any]            = aimpl.Power[P, C]
	TensorProduct[E, C, S any] = aimpl.TensorProduct[E, C, S]
	Tensor[E, S any]           = aimpl.Tensor[E, S]
)

func StructureIs[S aimpl.Structure[E], E any](s Structure[E]) bool {
	_, ok := s.(S)
	return ok
}

func StructureAs[S aimpl.Structure[E], E any](s Structure[E]) (S, error) {
	out, ok := s.(S)
	if !ok {
		return *new(S), errs.NewType("structure does not implement the expected type")
	}
	return out, nil
}
