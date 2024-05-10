package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

// Zn defines methods for S to behave like ring of integers modulo n.
type Zn[S algebra.Structure, E algebra.Element] interface {
	N[S, E]
	algebra.FiniteRing[S, E]
	IsDecomposable(coprimeIdealNorms ...Uint[S, E]) (bool, error)
}

// Uint defines methods for elements of type E to behave
// like elements of the ring of integers modulo n.
type Uint[S algebra.Structure, E algebra.Element] interface {
	Nat[S, E]
	algebra.FiniteRingElement[S, E]
}
