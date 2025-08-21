package impl

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// *** Magma

type magmaElement[E any] interface {
	Set(v E)
	ct.ConditionallySelectable[E]
	ct.Equatable[E]
	Add(lhs, rhs E)
	Double(E)

	SetBytes([]byte) (ok ct.Bool)
	Bytes() []byte
}

type MagmaElement[E magmaElement[E]] magmaElement[E]

type MagmaElementPtr[E MagmaElement[E], T any] interface {
	*T
	MagmaElement[E]
}

// *** Monoid

type monoidElement[E any] interface {
	magmaElement[E]
	SetZero()
	IsZero() ct.Bool
	IsNonZero() ct.Bool
}

type MonoidElement[E monoidElement[E]] monoidElement[E]

type MonoidElementPtr[E MonoidElement[E], T any] interface {
	*T
	MonoidElement[E]
}

// *** Group

type groupElement[E any] interface {
	monoidElement[E]
	Sub(lhs, rhs E)
	Neg(E)
}

type GroupElement[E groupElement[E]] groupElement[E]

type GroupElementPtr[E GroupElement[E], T any] interface {
	*T
	GroupElement[E]
}

// *** Ring

type ringElement[E any] interface {
	groupElement[E]
	SetOne()
	IsOne() ct.Bool
	Mul(lhs, rhs E)
	Square(E)
	Inv(E) (ok ct.Bool)
	Div(lhs, rhs E) (ok ct.Bool)
	Sqrt(E) (ok ct.Bool)
}

type RingElement[E ringElement[E]] ringElement[E]

type RingElementPtr[E RingElement[E], T any] interface {
	*T
	RingElement[E]
}

// *** Finite Field

type finiteFieldElement[E any] interface {
	ringElement[E]
	SetUniformBytes(componentsData ...[]byte) (ok ct.Bool)
	SetRandom(prng io.Reader) (ok ct.Bool)
	ComponentsBytes() [][]byte
	Degree() uint64
}

type FiniteFieldElement[E finiteFieldElement[E]] finiteFieldElement[E]

type FiniteFieldElementPtr[E FiniteFieldElement[E], T any] interface {
	*T
	FiniteFieldElement[E]
}

// *** Prime field

type primeFieldElement[E any] interface {
	finiteFieldElement[E]
	SetUint64(u uint64)
	SetLimbs(data []uint64) (ok ct.Bool)
	SetBytesWide(data []byte) (ok ct.Bool)
	Limbs() []uint64
}

type PrimeFieldElement[E primeFieldElement[E]] primeFieldElement[E]

type PrimeFieldElementPtr[E PrimeFieldElement[E], T any] interface {
	*T
	PrimeFieldElement[E]
}
