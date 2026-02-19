package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
)

type (
	Magma[E crtp.MagmaElement[E]]        = crtp.Magma[E]
	MagmaElement[E crtp.MagmaElement[E]] = crtp.MagmaElement[E]
)

type (
	SemiGroup[E crtp.SemiGroupElement[E]]        = crtp.SemiGroup[E]
	SemiGroupElement[E crtp.SemiGroupElement[E]] = crtp.SemiGroupElement[E]

	AdditiveSemiGroup[E crtp.AdditiveSemiGroupElement[E]]        = crtp.AdditiveSemiGroup[E]
	AdditiveSemiGroupElement[E crtp.AdditiveSemiGroupElement[E]] = crtp.AdditiveSemiGroupElement[E]

	MultiplicativeSemiGroup[E crtp.MultiplicativeSemiGroupElement[E]]        = crtp.MultiplicativeSemiGroup[E]
	MultiplicativeSemiGroupElement[E crtp.MultiplicativeSemiGroupElement[E]] = crtp.MultiplicativeSemiGroupElement[E]

	CyclicSemiGroup[E crtp.CyclicSemiGroupElement[E]]        = crtp.CyclicSemiGroup[E]
	CyclicSemiGroupElement[E crtp.CyclicSemiGroupElement[E]] = crtp.CyclicSemiGroupElement[E]
)

type (
	Monoid[ME crtp.MonoidElement[ME]]        = crtp.Monoid[ME]
	MonoidElement[ME crtp.MonoidElement[ME]] = crtp.MonoidElement[ME]

	AdditiveMonoid[ME crtp.AdditiveMonoidElement[ME]]        = crtp.AdditiveMonoid[ME]
	AdditiveMonoidElement[ME crtp.AdditiveMonoidElement[ME]] = crtp.AdditiveMonoidElement[ME]

	MultiplicativeMonoid[ME crtp.MultiplicativeMonoidElement[ME]]        = crtp.MultiplicativeMonoid[ME]
	MultiplicativeMonoidElement[ME crtp.MultiplicativeMonoidElement[ME]] = crtp.MultiplicativeMonoidElement[ME]

	CyclicMonoid[ME crtp.CyclicMonoidElement[ME]]        = crtp.CyclicMonoid[ME]
	CyclicMonoidElement[ME crtp.CyclicMonoidElement[ME]] = crtp.CyclicMonoidElement[ME]

	FiniteGroup[GE crtp.GroupElement[GE]] = crtp.FiniteGroup[GE]
)

type (
	Group[E crtp.GroupElement[E]]        = crtp.Group[E]
	GroupElement[E crtp.GroupElement[E]] = crtp.GroupElement[E]

	AdditiveGroup[E crtp.AdditiveGroupElement[E]]        = crtp.AdditiveGroup[E]
	AdditiveGroupElement[E crtp.AdditiveGroupElement[E]] = crtp.AdditiveGroupElement[E]

	MultiplicativeGroup[E crtp.MultiplicativeGroupElement[E]]        = crtp.MultiplicativeGroup[E]
	MultiplicativeGroupElement[E crtp.MultiplicativeGroupElement[E]] = crtp.MultiplicativeGroupElement[E]

	CyclicGroup[E crtp.CyclicGroupElement[E]]        = crtp.CyclicGroup[E]
	CyclicGroupElement[E crtp.CyclicGroupElement[E]] = crtp.CyclicGroupElement[E]
)

type (
	AbelianSemiGroup[E crtp.AbelianSemiGroupElement[E, S], S crtp.RingElement[S]]        = crtp.AbelianSemiGroup[E, S]
	AbelianSemiGroupElement[E crtp.AbelianSemiGroupElement[E, S], S crtp.RingElement[S]] = crtp.AbelianSemiGroupElement[E, S]
	// Ab ~= Mod_Z, however due to type system constraints we cannot express this directly without breaking some things (e.g. ZMod would have to be considered as a euclidean domain)
	// So we leave it under-constrained as a RingElement, just to satisfy properties of a module.
	AbelianGroup[E crtp.AbelianGroupElement[E, S], S crtp.RingElement[S]]        = crtp.AbelianGroup[E, S]
	AbelianGroupElement[E crtp.AbelianGroupElement[E, S], S crtp.RingElement[S]] = crtp.AbelianGroupElement[E, S]

	PrimeGroup[E crtp.PrimeGroupElement[E, S], S crtp.PrimeFieldElement[S]]        = crtp.PrimeGroup[E, S]
	PrimeGroupElement[E crtp.PrimeGroupElement[E, S], S crtp.PrimeFieldElement[S]] = crtp.PrimeGroupElement[E, S]

	AdditivePrimeGroup[E crtp.AdditivePrimeGroupElement[E, S], S crtp.PrimeFieldElement[S]]        = crtp.AdditivePrimeGroup[E, S]
	AdditivePrimeGroupElement[E crtp.AdditivePrimeGroupElement[E, S], S crtp.PrimeFieldElement[S]] = crtp.AdditivePrimeGroupElement[E, S]
)
