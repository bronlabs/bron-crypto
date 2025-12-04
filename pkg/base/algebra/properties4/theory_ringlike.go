package properties4

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// SemiRingTheory returns a complete theory for a semiring.
// A semiring has additive semigroup + multiplicative monoid + distributivity.
func SemiRingTheory[S algebra.Structure[E], E algebra.Element[E]](
	mulCommutative bool,
) Theory[S, E] {
	return SemiRingProperties[S, E](mulCommutative)
}

// RingTheory returns a complete theory for a ring.
// A ring has additive group + multiplicative monoid + distributivity + zero annihilation.
func RingTheory[S algebra.Structure[E], E algebra.Element[E]](
	mulCommutative bool,
) Theory[S, E] {
	return RingProperties[S, E](mulCommutative)
}

// FieldTheory returns a complete theory for a field.
// A field is a commutative ring where every non-zero element has a multiplicative inverse.
// Note: This requires a generator that produces only non-zero elements for
// the multiplicative inverse tests.
func FieldTheory[S algebra.Structure[E], E algebra.Element[E]]() Theory[S, E] {
	return FieldProperties[S, E]()
}
