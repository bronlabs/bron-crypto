package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type (
	Element[E any]             = crtp.Element[E]
	Structure[E any]           = crtp.Structure[E]
	NAry[C any]                = crtp.NAry[C]
	Mapping[F, C any]          = crtp.Mapping[F, C]
	Product[P, C any]          = crtp.Product[P, C]
	CoProduct[P, C any]        = crtp.CoProduct[P, C]
	Power[P, C any]            = crtp.Power[P, C]
	TensorProduct[E, C, S any] = crtp.TensorProduct[E, C, S]
	Tensor[E, S any]           = crtp.Tensor[E, S]
)

func StructureIs[S crtp.Structure[E], E any](s Structure[E]) bool {
	_, ok := s.(S)
	return ok
}

func StructureAs[S crtp.Structure[E], E any](s Structure[E]) (S, error) {
	out, ok := s.(S)
	if !ok {
		return *new(S), errs.NewType("structure does not implement the expected type")
	}
	return out, nil
}
