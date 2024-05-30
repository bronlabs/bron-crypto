package integer

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/cronokirby/saferith"
)

// Z defines methods for S for it to behave like the integers.
type Z[S algebra.Structure, E algebra.Element] interface {
	NaturalRig[S, E]
	algebra.EuclideanDomain[S, E]
}

// Int defines methods for element of type E to be elements of the integers S.
type Int[S algebra.Structure, E algebra.Element] interface {
	NaturalRigElement[S, E]
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
	Modulus() *saferith.Modulus
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

type ZnX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroup[G, E]
	algebra.BoundedOrderTheoreticLattice[G, E]
	algebra.Chain[G, E]

	Modulus() *saferith.Modulus
}

type IntX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroupElement[G, E]
	algebra.BoundedOrderTheoreticLatticeElement[G, E]
	algebra.ChainElement[G, E]
}
