package algebra

import (
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
)

type (
	Magma[E aimpl.MagmaElement[E]]        = aimpl.Magma[E]
	MagmaElement[E aimpl.MagmaElement[E]] = aimpl.MagmaElement[E]
)

type (
	SemiGroup[E aimpl.SemiGroupElement[E]]        = aimpl.SemiGroup[E]
	SemiGroupElement[E aimpl.SemiGroupElement[E]] = aimpl.SemiGroupElement[E]

	AdditiveSemiGroup[E aimpl.AdditiveSemiGroupElement[E]]        = aimpl.AdditiveSemiGroup[E]
	AdditiveSemiGroupElement[E aimpl.AdditiveSemiGroupElement[E]] = aimpl.AdditiveSemiGroupElement[E]

	MultiplicativeSemiGroup[E aimpl.MultiplicativeSemiGroupElement[E]]        = aimpl.MultiplicativeSemiGroup[E]
	MultiplicativeSemiGroupElement[E aimpl.MultiplicativeSemiGroupElement[E]] = aimpl.MultiplicativeSemiGroupElement[E]

	CyclicSemiGroup[E aimpl.CyclicSemiGroupElement[E]]        = aimpl.CyclicSemiGroup[E]
	CyclicSemiGroupElement[E aimpl.CyclicSemiGroupElement[E]] = aimpl.CyclicSemiGroupElement[E]
)

type (
	Monoid[ME aimpl.MonoidElement[ME]]        = aimpl.Monoid[ME]
	MonoidElement[ME aimpl.MonoidElement[ME]] = aimpl.MonoidElement[ME]

	AdditiveMonoid[ME aimpl.AdditiveMonoidElement[ME]]        = aimpl.AdditiveMonoid[ME]
	AdditiveMonoidElement[ME aimpl.AdditiveMonoidElement[ME]] = aimpl.AdditiveMonoidElement[ME]

	MultiplicativeMonoid[ME aimpl.MultiplicativeMonoidElement[ME]]        = aimpl.MultiplicativeMonoid[ME]
	MultiplicativeMonoidElement[ME aimpl.MultiplicativeMonoidElement[ME]] = aimpl.MultiplicativeMonoidElement[ME]

	UniqueFactorizationMonoid[ME aimpl.UniqueFactorizationMonoidElement[ME]]        = aimpl.UniqueFactorizationMonoid[ME]
	UniqueFactorizationMonoidElement[ME aimpl.UniqueFactorizationMonoidElement[ME]] = aimpl.UniqueFactorizationMonoidElement[ME]
)

type (
	Group[E aimpl.GroupElement[E]]        = aimpl.Group[E]
	GroupElement[E aimpl.GroupElement[E]] = aimpl.GroupElement[E]

	AdditiveGroup[E aimpl.AdditiveGroupElement[E]]        = aimpl.AdditiveGroup[E]
	AdditiveGroupElement[E aimpl.AdditiveGroupElement[E]] = aimpl.AdditiveGroupElement[E]

	MultiplicativeGroup[E aimpl.MultiplicativeGroupElement[E]]        = aimpl.MultiplicativeGroup[E]
	MultiplicativeGroupElement[E aimpl.MultiplicativeGroupElement[E]] = aimpl.MultiplicativeGroupElement[E]

	FiniteGroup[E aimpl.FiniteGroupElement[E]]        = aimpl.FiniteGroup[E]
	FiniteGroupElement[E aimpl.FiniteGroupElement[E]] = aimpl.FiniteGroupElement[E]
)

type (
	AbelianMonoid[ME aimpl.AbelianMonoidElement[ME, S], S aimpl.NatLike[S]]        = aimpl.AbelianMonoid[ME, S]
	AbelianMonoidElement[ME aimpl.AbelianMonoidElement[ME, S], S aimpl.NatLike[S]] = aimpl.AbelianMonoidElement[ME, S]

	FiniteAbelianMonoid[ME aimpl.FiniteAbelianMonoidElement[ME, S], S aimpl.UintLike[S]]        = aimpl.FiniteAbelianMonoid[ME, S]
	FiniteAbelianMonoidElement[ME aimpl.FiniteAbelianMonoidElement[ME, S], S aimpl.UintLike[S]] = aimpl.FiniteAbelianMonoidElement[ME, S]

	AbelianGroup[E aimpl.AbelianGroupElement[E, S], S aimpl.IntLike[S]]        = aimpl.AbelianGroup[E, S]
	AbelianGroupElement[E aimpl.AbelianGroupElement[E, S], S aimpl.IntLike[S]] = aimpl.AbelianGroupElement[E, S]

	FiniteAbelianGroup[E aimpl.FiniteAbelianGroupElement[E, S], S aimpl.UintLike[S]]        = aimpl.FiniteAbelianGroup[E, S]
	FiniteAbelianGroupElement[E aimpl.FiniteAbelianGroupElement[E, S], S aimpl.UintLike[S]] = aimpl.FiniteAbelianGroupElement[E, S]

	PrimeGroup[E aimpl.PrimeGroupElement[E, S], S aimpl.PrimeFieldElement[S]]        = aimpl.PrimeGroup[E, S]
	PrimeGroupElement[E aimpl.PrimeGroupElement[E, S], S aimpl.PrimeFieldElement[S]] = aimpl.PrimeGroupElement[E, S]

	AdditivePrimeGroup[E aimpl.AdditivePrimeGroupElement[E, S], S aimpl.PrimeFieldElement[S]]        = aimpl.AdditivePrimeGroup[E, S]
	AdditivePrimeGroupElement[E aimpl.AdditivePrimeGroupElement[E, S], S aimpl.PrimeFieldElement[S]] = aimpl.AdditivePrimeGroupElement[E, S]
)
