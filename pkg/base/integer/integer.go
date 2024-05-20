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

// type Z[S algebra.Structure, E algebra.Element] interface {
// 	IntegerRing[S, E]
// 	Arithmetic() SignedArithmetic[E]
// }

// Zn defines methods for S to behave like ring of integers modulo n.
type Zn[S algebra.Structure, E algebra.Element] interface {
	algebra.FiniteRing[S, E]
	algebra.BoundedOrderTheoreticLattice[S, E]
	NaturalSemiRing[S, E]

	IsDecomposable(coprimeIdealNorms ...Uint[S, E]) (bool, error)
}

// Uint defines methods for elements of type E to behave
// like elements of the ring of integers modulo n.
type Uint[S algebra.Structure, E algebra.Element] interface {
	algebra.FiniteRingElement[S, E]
	algebra.BoundedOrderTheoreticLatticeElement[S, E]
	NaturalSemiRingElement[S, E]
}

// Zp defines methods for S to behave the field of integers modulo prime.
type Zp[S algebra.Structure, E algebra.Element] interface {
	Z[S, E]
	Zn[S, E]
	algebra.FiniteField[S, E]
}

// IntP defines methods for elements of type E to behave as
// elements of the integer field modulo prime.
type IntP[S algebra.Structure, E algebra.Element] interface {
	Int[S, E]
	Uint[S, E]
	algebra.FiniteFieldElement[S, E]
}

type ZnX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroup[G, E]
	algebra.BoundedOrderTheoreticLattice[G, E]
	NaturalSemiRing[G, E]
}

type IntX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroupElement[G, E]
	NaturalSemiRingElement[G, E]
}
