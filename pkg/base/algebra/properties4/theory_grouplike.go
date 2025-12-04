package properties4

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// AdditiveSemiGroupTheory returns a complete theory for an additive semigroup.
func AdditiveSemiGroupTheory[S algebra.Structure[E], E algebra.Element[E]]() Theory[S, E] {
	return AdditiveSemiGroupProperties[S, E]()
}

// AdditiveMonoidTheory returns a complete theory for an additive monoid.
func AdditiveMonoidTheory[S algebra.Structure[E], E algebra.Element[E]]() Theory[S, E] {
	return AdditiveMonoidProperties[S, E]()
}

// AdditiveGroupTheory returns a complete theory for an additive group.
func AdditiveGroupTheory[S algebra.Structure[E], E algebra.Element[E]]() Theory[S, E] {
	return AdditiveGroupProperties[S, E]()
}

// MultiplicativeSemiGroupTheory returns a complete theory for a multiplicative semigroup.
func MultiplicativeSemiGroupTheory[S algebra.Structure[E], E algebra.Element[E]](
	commutative bool,
) Theory[S, E] {
	return MultiplicativeSemiGroupProperties[S, E](commutative)
}

// MultiplicativeMonoidTheory returns a complete theory for a multiplicative monoid.
func MultiplicativeMonoidTheory[S algebra.Structure[E], E algebra.Element[E]](
	commutative bool,
) Theory[S, E] {
	return MultiplicativeMonoidProperties[S, E](commutative)
}

// MultiplicativeGroupTheory returns a complete theory for a multiplicative group.
// Note: This assumes all elements have inverses (e.g., non-zero field elements).
func MultiplicativeGroupTheory[S algebra.Structure[E], E algebra.Element[E]](
	commutative bool,
) Theory[S, E] {
	return MultiplicativeGroupProperties[S, E](commutative)
}
