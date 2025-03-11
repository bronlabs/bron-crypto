package algebra

import "io"

// ****************** Module

type Module[ME ModuleElement[ME, S], S RingElement[S]] Group[ME]

type ModuleElement[ME GroupElement[ME], S RingElement[S]] interface {
	GroupElement[ME]
	ScalarMul(sc S) ME
}

// ****************** Vector Space

type VectorSpace[V Vector[V, S], S FieldElement[S]] Module[V, S]

type Vector[V ModuleElement[V, S], S FieldElement[S]] ModuleElement[V, S]

// ****************** Algebra

type Algebra[AE AlgebraElement[AE, S], S FieldElement[S]] interface {
	VectorSpace[AE, S]
	Ring[AE]
}

type AlgebraElement[AE interface {
	Vector[AE, S]
	RingElement[AE]
}, S FieldElement[S]] interface {
	Vector[AE, S]
	RingElement[AE]
}

// ******************* Polynomials

type PolynomialRing[P Polynomial[P, C], C FieldElement[C]] interface {
	Algebra[P, C]
	EuclideanDomain[P]

	New(coeffs ...C) P
	Random(degree int, freeCoeff C, prng io.Reader) (P, error)
}

type Polynomial[P interface {
	AlgebraElement[P, S]
	EuclideanDomainElement[P]
}, S FieldElement[S]] interface {
	AlgebraElement[P, S]
	EuclideanDomainElement[P]

	Coefficients() []S
	Degree() uint
	Eval(P) S
}

// ******************* Matrices

type MatrixAlgebra[M Matrix[M, C], C FieldElement[C]] interface {
	Algebra[M, C]

	New(n, m int) M
	Random(n, m int, prng io.Reader) (M, error)
}

type Matrix[M AlgebraElement[M, S], S FieldElement[S]] interface {
	AlgebraElement[M, S]

	IsSquare() bool
	Dimensions() (n int, m int)
}

type SquareMatrix[M Matrix[M, S], S FieldElement[S]] interface {
	Matrix[M, S]

	Determinant() S
	Inv() (M, error)
}
