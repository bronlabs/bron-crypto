package crtp

import (
	"fmt"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/cronokirby/saferith"
)

type Cardinal interface {
	base.Comparable[Cardinal]
	base.Clonable[Cardinal]
	base.Hashable[Cardinal]
	base.Transparent[*saferith.Nat]
	base.BytesLike
	fmt.Stringer

	Summand[Cardinal]
	Multiplicand[Cardinal]
	Minuend[Cardinal]

	Uint64() uint64
	Big() *big.Int
	IsZero() bool
	IsFinite() bool
	IsInfinite() bool
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
	// base.Comparable[E]
	// IsNegative() bool
	ArithmeticNegand[E]
}

type ZnLike[E any] interface {
	Ring[E]
	NLike[E]
	base.HashableStructure[E]
}

type UintLike[E any] interface {
	RingElement[E]
	NatLike[E]
	ArithmeticNegand[E]
}

type PrimeField[E any] interface {
	Field[E]
	ZnLike[E]
	BitLen() int
	FromWideBytes([]byte) (E, error)
	// WideElementSize returns the **maximum** number of bytes used to map uniformly to an element.
	WideElementSize() int
	FiniteStructure[E]
}

type PrimeFieldElement[E any] interface {
	FieldElement[E]
	UintLike[E]
}
