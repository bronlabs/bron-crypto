package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

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
