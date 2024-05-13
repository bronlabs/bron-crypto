package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

// Zn defines methods for S to behave like ring of integers modulo n.
type Zn[S algebra.Structure, E algebra.Element] interface {
	algebra.FiniteRing[S, E]
	algebra.BoundedOrderTheoreticLattice[S, E]
	NaturalNumberMonoid[S, E]

	IsDecomposable(coprimeIdealNorms ...Uint[S, E]) (bool, error)
}

// Uint defines methods for elements of type E to behave
// like elements of the ring of integers modulo n.
type Uint[S algebra.Structure, E algebra.Element] interface {
	algebra.FiniteRingElement[S, E]
	algebra.BoundedOrderTheoreticLatticeElement[S, E]
	NaturalNumberMonoidElement[S, E]
}
