package crtp

import (
	"fmt"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type Cardinal interface {
	base.Comparable[Cardinal]
	base.Clonable[Cardinal]
	base.Hashable[Cardinal]
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
	BitLen() uint
}

type NPlusLike[E any] interface {
	SemiRing[E]
	UniqueFactorizationMonoid[E]
	FromCardinal(Cardinal) (E, error)
}

type NatPlusLike[E any] interface {
	SemiRingElement[E]
	UniqueFactorizationMonoidElement[E]

	IsOdd() bool
	IsEven() bool
}

type NLike[E any] interface {
	NPlusLike[E]
	EuclideanSemiDomain[E]
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
	ArithmeticNegand[E]
}

type ZModLike[E any] interface {
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
	FiniteField[E]
	ZModLike[E]
	BitLen() int
	FromWideBytes([]byte) (E, error)
	// WideElementSize returns the **maximum** number of bytes used to map uniformly to an element.
	WideElementSize() int
	FiniteStructure[E]
	// FromNat expects a *numct.Nat value (using any to avoid import cycle)
	FromNat(*numct.Nat) (E, error)
	FromUint64(uint64) E
}

type PrimeFieldElement[E any] interface {
	FiniteFieldElement[E]
	UintLike[E]
}
