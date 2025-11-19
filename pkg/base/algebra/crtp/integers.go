package crtp

import (
	"fmt"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
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

type NumericStructure[E any] interface {
	FromBytesBE([]byte) (E, error)
}

type Numeric interface {
	BytesBE() []byte
}

type NPlusLike[E any] interface {
	SemiRing[E]
	UniqueFactorizationMonoid[E]
	NumericStructure[E]
	FromCardinal(Cardinal) (E, error)
}

type NatPlusLike[E any] interface {
	SemiRingElement[E]
	UniqueFactorizationMonoidElement[E]
	Numeric

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
	FromCardinal(Cardinal) (E, error)
}

type IntLike[E any] interface {
	EuclideanDomainElement[E]
	ArithmeticNegand[E]

	IsEven() bool
	IsOdd() bool
	IsPositive() bool
	IsNegative() bool
	IsZero() bool
	Cardinal() Cardinal
}

type ZModLike[E any] interface {
	Ring[E]
	NLike[E]
	base.HashableStructure[E]
	FromBytesBEReduce([]byte) (E, error)
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
	NumericStructure[E]
	FromUint64(uint64) E
}

type PrimeFieldElement[E any] interface {
	FiniteFieldElement[E]
	UintLike[E]
}
