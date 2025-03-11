package groups

import (
	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type (
	Group[E algebra.GroupElement[E]]        algebra.Group[E]
	GroupElement[E algebra.GroupElement[E]] algebra.GroupElement[E]

	AdditiveGroup[E algebra.AdditiveGroupElement[E]]        algebra.AdditiveGroup[E]
	AdditiveGroupElement[E algebra.AdditiveGroupElement[E]] algebra.AdditiveGroupElement[E]

	MultiplicativeGroup[E algebra.MultiplicativeGroupElement[E]]        algebra.MultiplicativeGroup[E]
	MultiplicativeGroupElement[E algebra.MultiplicativeGroupElement[E]] algebra.MultiplicativeGroupElement[E]

	MultiplicativeGroupWithZero[E algebra.MultiplicativeGroupWithZeroElement[E]]        algebra.MultiplicativeGroupWithZero[E]
	MultiplicativeGroupWithZeroElement[E algebra.MultiplicativeGroupWithZeroElement[E]] algebra.MultiplicativeGroupWithZeroElement[E]

	AbelianGroup[E algebra.AbelianGroupElement[E, S], S algebra.RingElement[S]]        algebra.AbelianGroup[E, S]
	AbelianGroupElement[E algebra.AbelianGroupElement[E, S], S algebra.RingElement[S]] algebra.AbelianGroupElement[E, S]

	PrimeGroup[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]]        algebra.PrimeGroup[E, S]
	PrimeGroupElement[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] algebra.PrimeGroupElement[E, S]
)

func NewNonZeroMultiplicativeGroupWithZeroElement[E MultiplicativeGroupWithZeroElement[E]](e E) (*NonZeroMultiplicativeGroupWithZeroElement[E], error) {
	if e.IsZero() {
		return nil, errs.NewIsZero("zero is not a non-zero element")
	}
	return &NonZeroMultiplicativeGroupWithZeroElement[E]{e}, nil
}

type NonZeroMultiplicativeGroupWithZeroElement[E interface {
	MultiplicativeGroupWithZeroElement[E]
}] struct {
	MultiplicativeGroupWithZeroElement[E]
}

func (e NonZeroMultiplicativeGroupWithZeroElement[E]) Div(rhs E) E {
	if rhs.IsZero() {
		panic("division by zero")
	}
	out, err := e.MultiplicativeGroupWithZeroElement.TryDiv(rhs)
	if err != nil {
		panic(errs.WrapIsZero(err, "division by zero"))
	}
	return out
}
