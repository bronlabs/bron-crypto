package crtp

import "github.com/bronlabs/bron-crypto/pkg/base"

// ******************** Magma

type Magma[E any] Structure[E]
type MagmaElement[E any] interface {
	Element[E]
	Operand[E]
}

// ******************** SemiGroup

type SemiGroup[E any] Magma[E]

type SemiGroupElement[E any] MagmaElement[E]

type AdditiveSemiGroup[E any] SemiGroup[E]

type AdditiveSemiGroupElement[E any] interface {
	SemiGroupElement[E]
	Summand[E]

	Double() E
}

type MultiplicativeSemiGroup[E any] SemiGroup[E]

type MultiplicativeSemiGroupElement[E any] interface {
	SemiGroupElement[E]
	Multiplicand[E]

	Square() E
}

type CyclicSemiGroup[E any] interface {
	SemiGroup[E]
	Generator() E
}

type CyclicSemiGroupElement[E any] interface {
	SemiGroupElement[E]
	IsDesignatedGenerator() bool
}

// ******************** Monoid

type Monoid[ME any] interface {
	SemiGroup[ME]
	OpIdentity() ME
}

type MonoidElement[ME any] interface {
	SemiGroupElement[ME]
	IsOpIdentity() bool

	TryOpInv() (ME, error)
}

type AdditiveMonoid[ME any] interface {
	Monoid[ME]
	AdditiveSemiGroup[ME]
	Zero() ME
}

type AdditiveMonoidElement[ME any] interface {
	MonoidElement[ME]
	AdditiveSemiGroupElement[ME]

	IsZero() bool
	MaybeArithmeticNegand[ME]
	MaybeMinuend[ME]
}

type MultiplicativeMonoid[ME any] interface {
	Monoid[ME]
	MultiplicativeSemiGroup[ME]
	One() ME
}

type MultiplicativeMonoidElement[ME any] interface {
	MonoidElement[ME]
	MultiplicativeSemiGroupElement[ME]

	IsOne() bool
	MaybeInversand[ME]
	MaybeDividend[ME]
}

type UniqueFactorizationMonoid[ME any] Monoid[ME]

type UniqueFactorizationMonoidElement[ME any] interface {
	MonoidElement[ME]
	IsProbablyPrime() bool
}

// ******************** Group

type Group[GE any] Monoid[GE]

type GroupElement[GE any] interface {
	MonoidElement[GE]
	OpInv() GE
}

type AdditiveGroup[E any] interface {
	Group[E]
	AdditiveMonoid[E]
}

type AdditiveGroupElement[E any] interface {
	GroupElement[E]
	AdditiveMonoidElement[E]
	ArithmeticNegand[E]
	Minuend[E]
}

type MultiplicativeGroup[E any] interface {
	Group[E]
	MultiplicativeMonoid[E]
}

type MultiplicativeGroupElement[E any] interface {
	GroupElement[E]
	MultiplicativeMonoidElement[E]
	Dividend[E]
	Inversand[E]
}

// ************** Extra Monoids

type AbelianMonoid[E, S any] SemiModule[E, S]

type AbelianMonoidElement[E, S any] SemiModuleElement[E, S]

// **************** Extra Groups

type AbelianGroup[E, S any] interface {
	ZLikeModule[E, S]
	AbelianMonoid[E, S]
}

type AbelianGroupElement[E, S any] interface {
	ZLikeModuleElement[E, S]
	AbelianMonoidElement[E, S]
}

type PrimeGroup[E, S any] interface {
	base.HashableStructure[E]
	AbelianGroup[E, S]
	VectorSpace[E, S]
	CyclicSemiGroup[E]
	ScalarBaseOp(S) E
}

type PrimeGroupElement[E, S any] interface {
	AbelianGroupElement[E, S]
	Vector[E, S]
	CyclicSemiGroupElement[E]
}

type AdditivePrimeGroup[E, S any] interface {
	PrimeGroup[E, S]
	AdditiveModule[E, S]
	ScalarBaseMul(S) E
}

type AdditivePrimeGroupElement[E, S any] interface {
	PrimeGroupElement[E, S]
	AdditiveModuleElement[E, S]
}
