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
	UnsignedNumeric
	fmt.Stringer

	Summand[Cardinal]
	Multiplicand[Cardinal]

	Uint64() uint64
	Big() *big.Int
	IsZero() bool
	IsFinite() bool
	IsUnknown() bool
	IsProbablyPrime() bool
	BitLen() int
}

type UnsignedNumericStructure[E any] interface {
	FromBytesBE([]byte) (E, error)
}

type UnsignedNumeric interface {
	BytesBE() []byte
}

type SignedNumericStructure[E any] interface {
	FromTwosComplementBytesBE([]byte) (E, error)
}
type SignedNumeric interface {
	AbsBytesBE() []byte
	TwosComplementBytesBE() []byte
}

type NPlusLike[E any] interface {
	HemiRing[E]
	UnsignedNumericStructure[E]
	FromCardinal(Cardinal) (E, error)
}

type NatPlusLike[E any] interface {
	HemiRingElement[E]
	UnsignedNumeric
	IsProbablyPrime() bool

	IsOdd() bool
	IsEven() bool
	Cardinal() Cardinal
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
}

type ZLike[E any] interface {
	SignedNumericStructure[E]
	EuclideanDomain[E]
}

type IntLike[E any] interface {
	SignedNumeric
	EuclideanDomainElement[E]
	IsProbablyPrime() bool

	IsEven() bool
	IsOdd() bool
	IsPositive() bool
	IsNegative() bool
	IsZero() bool
}

type ZModLike[E any] interface {
	Ring[E]
	NLike[E]
	FiniteStructure[E]
	FromBytesBEReduce([]byte) (E, error)
}

type UintLike[E any] interface {
	RingElement[E]
	NatLike[E]
}

type PrimeField[E any] interface {
	FiniteField[E]
	ZModLike[E]
	BitLen() int
	FromWideBytes([]byte) (E, error)
	// WideElementSize returns the **maximum** number of bytes used to map uniformly to an element.
	WideElementSize() int
	FromUint64(uint64) E
}

type PrimeFieldElement[E any] interface {
	FiniteFieldElement[E]
	UintLike[E]
}
