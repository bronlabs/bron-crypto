package algebra

import (
	"io"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
)

// ****************** Action

type Actable[E Element[E], S SemiGroupElement[S]] interface {
	Element[E]
	ScalarMul(actor S) E
}

type RingActable[E Element[E], S RingElement[S]] Actable[E, S]

// ****************** Module

type Module[ME ModuleElement[ME, S], S RingElement[S]] Group[ME]

type ModuleElement[ME GroupElement[ME], S RingElement[S]] interface {
	GroupElement[ME]
	RingActable[ME, S]
	IsTorsionFree() bool
}

// ****************** Vector Space

type VectorSpace[V Vector[V, S], S FieldElement[S]] Module[V, S]

type Vector[V ModuleElement[V, S], S FieldElement[S]] ModuleElement[V, S]

// ****************** Algebra

type Algebra[AE AlgebraElement[AE, S], S RingElement[S]] interface {
	Module[AE, S]
	Ring[AE]
}

type AlgebraElement[AE interface {
	ModuleElement[AE, S]
	RingElement[AE]
}, S RingElement[S]] interface {
	ModuleElement[AE, S]
	RingElement[AE]
}

// ******************* Polynomials

type PolynomialRing[P Polynomial[P, C], C RingElement[C]] interface {
	Algebra[P, C]
	EuclideanDomain[P]

	New(coeffs ...C) P
	Random(degree int, freeCoeff C, prng io.Reader) (P, error)
}

type Polynomial[P interface {
	AlgebraElement[P, S]
	EuclideanDomainElement[P]
}, S RingElement[S]] interface {
	AlgebraElement[P, S]
	EuclideanDomainElement[P]

	Coefficients() []S
	Derivative() Polynomial[P, S]
	Degree() uint
	Eval(S) S
}

// ******************* Matrices

type Matrix[M Element[M], C RingElement[C]] interface {
	ds.AbstractMatrix[M]
	RingActable[M, C]
	TryInv() (M, error)
}

type MatrixAlgebra[M SquareMatrix[M, C], C FieldElement[C]] interface {
	Algebra[M, C]

	New(n, m int) M
	Random(n, m int, prng io.Reader) (M, error)
}

type SquareMatrix[M interface {
	Matrix[M, S]
	AlgebraElement[M, S]
}, S FieldElement[S]] interface {
	Matrix[M, S]
	AlgebraElement[M, S]

	Determinant() S
}
