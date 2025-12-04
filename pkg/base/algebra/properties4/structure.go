package properties4

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"pgregory.net/rapid"
)

// Structure represents an algebraic structure with semantic operators.
// It holds the carrier (the underlying type), a generator for testing,
// and optional addition/multiplication operators.
type Structure[S algebra.Structure[E], E algebra.Element[E]] struct {
	// Carrier is the algebraic structure (e.g., num.NPlus, field.Fp, etc.)
	Carrier S
	// Generator produces random elements for property testing.
	Generator *rapid.Generator[E]
	// Add is the addition operator (nil if not applicable).
	Add *BinaryOp[E]
	// Mul is the multiplication operator (nil if not applicable).
	Mul *BinaryOp[E]
}

// NewStructure creates a new structure with carrier and generator.
func NewStructure[S algebra.Structure[E], E algebra.Element[E]](
	carrier S,
	gen *rapid.Generator[E],
) *Structure[S, E] {
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gen,
	}
}

// WithAddition sets the addition operator.
func (s *Structure[S, E]) WithAddition(add *BinaryOp[E]) *Structure[S, E] {
	s.Add = add
	return s
}

// WithMultiplication sets the multiplication operator.
func (s *Structure[S, E]) WithMultiplication(mul *BinaryOp[E]) *Structure[S, E] {
	s.Mul = mul
	return s
}

// Introspection methods

// HasAddition returns true if addition is defined.
func (s *Structure[S, E]) HasAddition() bool {
	return s.Add != nil
}

// HasMultiplication returns true if multiplication is defined.
func (s *Structure[S, E]) HasMultiplication() bool {
	return s.Mul != nil
}

// IsAdditiveSemiGroup returns true if the structure has associative, closed addition.
func (s *Structure[S, E]) IsAdditiveSemiGroup() bool {
	return s.Add != nil
}

// IsAdditiveMonoid returns true if the structure is an additive semigroup with identity.
func (s *Structure[S, E]) IsAdditiveMonoid() bool {
	return s.Add != nil && s.Add.HasIdentity()
}

// IsAdditiveGroup returns true if the structure is an additive monoid with inverses.
func (s *Structure[S, E]) IsAdditiveGroup() bool {
	return s.Add != nil && s.Add.HasIdentity() && s.Add.HasInverse()
}

// IsMultiplicativeSemiGroup returns true if the structure has associative, closed multiplication.
func (s *Structure[S, E]) IsMultiplicativeSemiGroup() bool {
	return s.Mul != nil
}

// IsMultiplicativeMonoid returns true if the structure is a multiplicative semigroup with identity.
func (s *Structure[S, E]) IsMultiplicativeMonoid() bool {
	return s.Mul != nil && s.Mul.HasIdentity()
}

// IsMultiplicativeGroup returns true if the structure is a multiplicative monoid with inverses.
func (s *Structure[S, E]) IsMultiplicativeGroup() bool {
	return s.Mul != nil && s.Mul.HasIdentity() && s.Mul.HasInverse()
}

// IsSemiRing returns true if the structure has additive semigroup + multiplicative monoid.
func (s *Structure[S, E]) IsSemiRing() bool {
	return s.IsAdditiveSemiGroup() && s.IsMultiplicativeMonoid()
}

// IsRing returns true if the structure has additive group + multiplicative monoid.
func (s *Structure[S, E]) IsRing() bool {
	return s.IsAdditiveGroup() && s.IsMultiplicativeMonoid()
}

// IsCommutativeRing returns true if the structure is a ring with commutative multiplication.
func (s *Structure[S, E]) IsCommutativeRing() bool {
	return s.IsRing() && s.Mul.IsCommutative()
}

// IsField returns true if the structure is a commutative ring with multiplicative inverses.
func (s *Structure[S, E]) IsField() bool {
	return s.IsCommutativeRing() && s.Mul.HasInverse()
}
