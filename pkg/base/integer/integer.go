package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

// Z defines methods for S for it to behave like the integers.
type Z[S algebra.Structure, E algebra.Element] interface {
	NaturalSemiRing[S, E]
	algebra.EuclideanDomain[S, E]
}

// Int defines methods for element of type E to be elements of the integers S.
type Int[S algebra.Structure, E algebra.Element] interface {
	NaturalSemiRingElement[S, E]
	algebra.EuclideanDomainElement[S, E]

	Abs() E
	Neg() E
}

// Zn defines methods for S to behave like ring of integers modulo n.
type Zn[S algebra.Structure, E algebra.Element] interface {
	Z[S, E]
	algebra.FiniteRing[S, E]
	algebra.BoundedOrderTheoreticLattice[S, E]

	IsDecomposable(coprimeModulusFactors ...E) bool
}

// Uint defines methods for elements of type E to behave
// like elements of the ring of integers modulo n.
type Uint[S algebra.Structure, E algebra.Element] interface {
	Int[S, E]
	algebra.FiniteRingElement[S, E]
	algebra.BoundedOrderTheoreticLatticeElement[S, E]
}

// Zp defines methods for S to behave the field of integers modulo prime.
type Zp[S algebra.Structure, E algebra.Element] interface {
	Zn[S, E]
	algebra.FiniteField[S, E]
}

// IntP defines methods for elements of type E to behave as
// elements of the integer field modulo prime.
type IntP[S algebra.Structure, E algebra.Element] interface {
	Uint[S, E]
	algebra.FiniteFieldElement[S, E]
}
