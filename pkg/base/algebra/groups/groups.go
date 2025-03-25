package groups

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type (
	Group[E algebra.GroupElement[E]]        algebra.Group[E]
	GroupElement[E algebra.GroupElement[E]] algebra.GroupElement[E]

	AdditiveGroup[E algebra.AdditiveGroupElement[E]]        algebra.AdditiveGroup[E]
	AdditiveGroupElement[E algebra.AdditiveGroupElement[E]] algebra.AdditiveGroupElement[E]

	MultiplicativeGroup[E algebra.MultiplicativeGroupElement[E]]        algebra.MultiplicativeGroup[E]
	MultiplicativeGroupElement[E algebra.MultiplicativeGroupElement[E]] algebra.MultiplicativeGroupElement[E]

	AbelianGroup[E algebra.AbelianGroupElement[E, S], S algebra.IntLike[S]]        algebra.AbelianGroup[E, S]
	AbelianGroupElement[E algebra.AbelianGroupElement[E, S], S algebra.IntLike[S]] algebra.AbelianGroupElement[E, S]

	FiniteAbelianGroup[E algebra.FiniteAbelianGroupElement[E, S], S algebra.UintLike[S]]        algebra.FiniteAbelianGroup[E, S]
	FiniteAbelianGroupElement[E algebra.FiniteAbelianGroupElement[E, S], S algebra.UintLike[S]] algebra.FiniteAbelianGroupElement[E, S]

	PrimeGroup[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]]        algebra.PrimeGroup[E, S]
	PrimeGroupElement[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] algebra.PrimeGroupElement[E, S]
)

func GetGroup[GE GroupElement[GE]](ge GE) Group[GE] {
	g, ok := ge.Structure().(Group[GE])
	if !ok {
		panic(errs.NewType("GroupElement does not have a Group structure"))
	}
	return g
}

func GetAdditiveGroup[GE AdditiveGroupElement[GE]](ge GE) AdditiveGroup[GE] {
	f, ok := ge.Structure().(AdditiveGroup[GE])
	if !ok {
		panic(errs.NewType("GroupElement does not have an AdditiveGroup structure"))
	}
	return f
}

func GetMultiplicativeGroup[GE MultiplicativeGroupElement[GE]](ge GE) MultiplicativeGroup[GE] {
	f, ok := ge.Structure().(MultiplicativeGroup[GE])
	if !ok {
		panic(errs.NewType("GroupElement does not have a MultiplicativeGroup structure"))
	}
	return f
}
