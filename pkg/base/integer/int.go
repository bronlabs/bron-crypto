package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

// Z defines methods for S for it to behave like the integers.
type Z[S algebra.Structure, E algebra.Element] interface {
	NaturalNumberMonoid[S, E]
	algebra.Field[S, E]
}

// Int defines methods for element of type E to be elements of the integers S.
type Int[S algebra.Structure, E algebra.Element] interface {
	NaturalNumberMonoidElement[S, E]
	algebra.FieldElement[S, E]

	Abs() E
	Neg() E
}
