package impl

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type monoidElementLowLevel[E any] interface {
	Set(v E)
	ct.ConditionallySelectable[E]
	ct.Equatable[E]
	Add(lhs, rhs E)
	Double(E)

	SetBytes([]byte) (ok ct.Bool)
	Bytes() []byte
	SetZero()
	IsZero() ct.Bool
	IsNonZero() ct.Bool
}

type MonoidElementLowLevel[E monoidElementLowLevel[E]] monoidElementLowLevel[E]

type MonoidElementPtrLowLevel[E MonoidElementLowLevel[E], T any] interface {
	*T
	MonoidElementLowLevel[E]
}

// *** Group.

type groupElementLowLevel[E any] interface {
	monoidElementLowLevel[E]
	Sub(lhs, rhs E)
	Neg(E)
}

type GroupElementLowLevel[E groupElementLowLevel[E]] groupElementLowLevel[E]

type GroupElementPtrLowLevel[E GroupElementLowLevel[E], T any] interface {
	*T
	GroupElementLowLevel[E]
}

type finiteGroupElementLowLevel[E any] interface {
	groupElementLowLevel[E]
	SetRandom(prng io.Reader) (ok ct.Bool)
}

type FiniteGroupElementLowLevel[E finiteGroupElementLowLevel[E]] finiteGroupElementLowLevel[E]

type FiniteGroupElementPtrLowLevel[E FiniteGroupElementLowLevel[E], T any] interface {
	*T
	FiniteGroupElementLowLevel[E]
}

// *** Ring.

type ringElementLowLevel[E any] interface {
	groupElementLowLevel[E]
	SetOne()
	IsOne() ct.Bool
	Mul(lhs, rhs E)
	Square(E)
	Inv(E) (ok ct.Bool)
	Div(lhs, rhs E) (ok ct.Bool)
	Sqrt(E) (ok ct.Bool)
}

type RingElementLowLevel[E ringElementLowLevel[E]] ringElementLowLevel[E]

type RingElementPtrLowLevel[E RingElementLowLevel[E], T any] interface {
	*T
	RingElementLowLevel[E]
}

// *** Finite Field.

type finiteFieldElementLowLevel[E any] interface {
	ringElementLowLevel[E]
	finiteGroupElementLowLevel[E]
	SetUniformBytes(componentsData ...[]byte) (ok ct.Bool)
	ComponentsBytes() [][]byte
	Degree() uint64
}

type FiniteFieldElementLowLevel[E finiteFieldElementLowLevel[E]] finiteFieldElementLowLevel[E]

type FiniteFieldElementPtrLowLevel[E FiniteFieldElementLowLevel[E], T any] interface {
	*T
	FiniteFieldElementLowLevel[E]
}

// *** Prime field.

type primeFieldElementLowLevel[E any] interface {
	finiteFieldElementLowLevel[E]
	SetUint64(u uint64)
	SetLimbs(data []uint64) (ok ct.Bool)
	SetBytesWide(data []byte) (ok ct.Bool)
	Limbs() []uint64
}

type PrimeFieldElementLowLevel[E primeFieldElementLowLevel[E]] primeFieldElementLowLevel[E]

type PrimeFieldElementPtrLowLevel[E PrimeFieldElementLowLevel[E], T any] interface {
	*T
	PrimeFieldElementLowLevel[E]
}
