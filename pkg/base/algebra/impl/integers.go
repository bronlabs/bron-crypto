package impl

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/cronokirby/saferith"
)

type Cardinal interface {
	base.Comparable[Cardinal]
	base.Equatable[Cardinal]
	base.Transparent[*saferith.Nat]
	base.BytesLike
	fmt.Stringer

	Summand[Cardinal]
	Multiplicand[Cardinal]
	Minuend[Cardinal]

	Uint64() uint64
	IsZero() bool
	IsFinite() bool
	IsUnknown() bool
	IsProbablyPrime() bool
}

type NPlusLike[E any] interface {
	SemiRing[E]
}

type NatPlusLike[E any] interface {
	SemiRingElement[E]

	IsOdd() bool
	IsEven() bool
}

type NLike[E any] interface {
	NPlusLike[E]
	EuclideanSemiDomain[E]
	FromUint64(uint64) E
	FromCardinal(Cardinal) (E, error)
}

type NatLike[E any] interface {
	NatPlusLike[E]
	EuclideanSemiDomainElement[E]

	IsPositive() bool
	IsZero() bool
	Cardinal() Cardinal
}

type ZLike[E any] interface {
	EuclideanDomain[E]
	NLike[E]
}

type IntLike[E any] interface {
	EuclideanDomainElement[E]
	IsNegative() bool
}

type ZnLike[E any] interface {
	NLike[E]
	FiniteRing[E]
}

type UintLike[E any] interface {
	NatLike[E]
	FiniteRingElement[E]
}

type PrimeField[E any] interface {
	FiniteField[E]
	ZnLike[E]
}

type PrimeFieldElement[E any] interface {
	FiniteFieldElement[E]
	UintLike[E]
}
