package constructions

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

func NewRegularAlgebra[R algebra.Ring[E], E algebra.RingElement[E]](r R) (*RegularAlgebra[R, E], error) {
	if utils.IsNil(r) {
		return nil, ErrInvalidArgument.WithMessage("ring is nil")
	}
	out := &RegularAlgebra[R, E]{
		RegularAlgebra: traits.RegularAlgebra[R, E, *RegularAlgebraElement[E], RegularAlgebraElement[E]]{
			RegularModule: traits.RegularModule[R, E, *RegularAlgebraElement[E], RegularAlgebraElement[E]]{
				Ring: r,
			},
		},
	}

	var _ algebra.Algebra[*RegularAlgebraElement[E], E] = out
	return out, nil
}

func NewFiniteRegularAlgebra[R algebra.FiniteRing[E], E algebra.RingElement[E]](r R) (*FiniteRegularAlgebra[R, E], error) {
	if utils.IsNil(r) {
		return nil, ErrInvalidArgument.WithMessage("ring is nil")
	}
	out := &FiniteRegularAlgebra[R, E]{
		RegularAlgebra: traits.RegularAlgebra[R, E, *FiniteRegularAlgebraElement[E], FiniteRegularAlgebraElement[E]]{
			RegularModule: traits.RegularModule[R, E, *FiniteRegularAlgebraElement[E], FiniteRegularAlgebraElement[E]]{
				Ring: r,
			},
		},
		FiniteRegularStructure: traits.FiniteRegularStructure[R, E, *FiniteRegularAlgebraElement[E], FiniteRegularAlgebraElement[E]]{
			R: r,
		},
	}

	var _ algebra.Algebra[*FiniteRegularAlgebraElement[E], E] = out
	return out, nil
}

type RegularAlgebra[R algebra.Ring[E], E algebra.RingElement[E]] struct {
	traits.RegularAlgebra[R, E, *RegularAlgebraElement[E], RegularAlgebraElement[E]]
}

type RegularAlgebraElement[E algebra.RingElement[E]] struct {
	traits.RegularAlgebraElement[E, *RegularAlgebraElement[E], RegularAlgebraElement[E]]
}

func (m *RegularAlgebraElement[E]) IsTorsionFree() bool {
	ring := algebra.StructureMustBeAs[algebra.Ring[E]](m.ScalarStructure())
	out, _ := NewRegularAlgebra(ring)
	return out.IsDomain()
}

func (m *RegularAlgebraElement[E]) Structure() algebra.Structure[*RegularAlgebraElement[E]] {
	ring := algebra.StructureMustBeAs[algebra.Ring[E]](m.ScalarStructure())
	out, _ := NewRegularAlgebra(ring)
	return out
}

type FiniteRegularAlgebra[R algebra.FiniteRing[E], E algebra.RingElement[E]] struct {
	traits.RegularAlgebra[R, E, *FiniteRegularAlgebraElement[E], FiniteRegularAlgebraElement[E]]
	traits.FiniteRegularStructure[R, E, *FiniteRegularAlgebraElement[E], FiniteRegularAlgebraElement[E]]
}

type FiniteRegularAlgebraElement[E algebra.RingElement[E]] struct {
	traits.RegularAlgebraElement[E, *FiniteRegularAlgebraElement[E], FiniteRegularAlgebraElement[E]]
}

func (m *FiniteRegularAlgebraElement[E]) IsTorsionFree() bool {
	ring := algebra.StructureMustBeAs[algebra.FiniteRing[E]](m.ScalarStructure())
	out, _ := NewRegularAlgebra(ring)
	return out.IsDomain()
}

func (m *FiniteRegularAlgebraElement[E]) Structure() algebra.Structure[*FiniteRegularAlgebraElement[E]] {
	ring := algebra.StructureMustBeAs[algebra.FiniteRing[E]](m.ScalarStructure())
	out, _ := NewFiniteRegularAlgebra(ring)
	return out
}
