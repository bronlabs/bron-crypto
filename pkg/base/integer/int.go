package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

// Z defines methods for S for it to behave like the integers.
type Z[S algebra.Structure, E algebra.Element] interface {
	N[S, E]
	algebra.EuclideanDomain[S, E]
}

// Int defines methods for element of type E to be elements of the integers S.
type Int[S algebra.Structure, E algebra.Element] interface {
	Nat[S, E]
	algebra.EuclideanDomainElement[S, E]
}
