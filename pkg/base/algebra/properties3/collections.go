package properties3

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// SemiGroupTraits returns traits for testing a semigroup.
// A semigroup has a closed, associative binary operation.
func SemiGroupTraits[S algebra.SemiGroup[E], E algebra.SemiGroupElement[E]](
	opName string,
	op func(a, b E) E,
	isCommutative bool,
) []Trait[S, E] {
	traits := []Trait[S, E]{
		&ClosureTrait[S, E]{OpName: opName, Op: op},
		&AssociativityTrait[S, E]{OpName: opName, Op: op},
	}
	if isCommutative {
		traits = append(traits, &CommutativityTrait[S, E]{OpName: opName, Op: op})
	}
	return traits
}

// MonoidTraits returns traits for testing a monoid.
// A monoid is a semigroup with an identity element.
func MonoidTraits[S algebra.Monoid[E], E algebra.MonoidElement[E]](
	opName string,
	op func(a, b E) E,
	identity func(s S) E,
	isCommutative bool,
) []Trait[S, E] {
	traits := SemiGroupTraits[S, E](opName, op, isCommutative)
	traits = append(traits, &IdentityTrait[S, E]{
		OpName:   opName,
		Op:       op,
		Identity: identity,
	})
	return traits
}

// GroupTraits returns traits for testing a group.
// A group is a monoid where every element has an inverse.
func GroupTraits[S algebra.Group[E], E algebra.GroupElement[E]](
	opName string,
	op func(a, b E) E,
	inv func(a E) E,
	identity func(s S) E,
	isCommutative bool,
) []Trait[S, E] {
	traits := MonoidTraits[S, E](opName, op, identity, isCommutative)
	traits = append(traits, &InverseTrait[S, E]{
		OpName:   opName,
		Op:       op,
		Inv:      inv,
		Identity: identity,
	})
	return traits
}

// AdditiveSemiGroupTraits returns traits for an additive semigroup.
func AdditiveSemiGroupTraits[S algebra.AdditiveSemiGroup[E], E algebra.AdditiveSemiGroupElement[E]]() []Trait[S, E] {
	return SemiGroupTraits[S, E](
		"Add",
		func(a, b E) E { return a.Add(b) },
		true, // addition is always commutative
	)
}

// AdditiveMonoidTraits returns traits for an additive monoid.
func AdditiveMonoidTraits[S algebra.AdditiveMonoid[E], E algebra.AdditiveMonoidElement[E]](
	s S,
) []Trait[S, E] {
	return MonoidTraits[S, E](
		"Add",
		func(a, b E) E { return a.Add(b) },
		func(s S) E { return s.Zero() },
		true, // addition is always commutative
	)
}

// AdditiveGroupTraits returns traits for an additive group.
func AdditiveGroupTraits[S algebra.AdditiveGroup[E], E algebra.AdditiveGroupElement[E]](
	s S,
) []Trait[S, E] {
	return GroupTraits[S, E](
		"Add",
		func(a, b E) E { return a.Add(b) },
		func(a E) E { return a.Neg() },
		func(s S) E { return s.Zero() },
		true, // addition is always commutative
	)
}

// MultiplicativeSemiGroupTraits returns traits for a multiplicative semigroup.
func MultiplicativeSemiGroupTraits[S algebra.MultiplicativeSemiGroup[E], E algebra.MultiplicativeSemiGroupElement[E]](
	isCommutative bool,
) []Trait[S, E] {
	return SemiGroupTraits[S, E](
		"Mul",
		func(a, b E) E { return a.Mul(b) },
		isCommutative,
	)
}

// MultiplicativeMonoidTraits returns traits for a multiplicative monoid.
func MultiplicativeMonoidTraits[S algebra.MultiplicativeMonoid[E], E algebra.MultiplicativeMonoidElement[E]](
	s S,
	isCommutative bool,
) []Trait[S, E] {
	return MonoidTraits[S, E](
		"Mul",
		func(a, b E) E { return a.Mul(b) },
		func(s S) E { return s.One() },
		isCommutative,
	)
}

// MultiplicativeGroupTraits returns traits for a multiplicative group.
func MultiplicativeGroupTraits[S algebra.MultiplicativeGroup[E], E algebra.MultiplicativeGroupElement[E]](
	s S,
	isCommutative bool,
) []Trait[S, E] {
	return GroupTraits[S, E](
		"Mul",
		func(a, b E) E { return a.Mul(b) },
		func(a E) E { return a.Inv() },
		func(s S) E { return s.One() },
		isCommutative,
	)
}

// DistributivityTraits returns traits for testing distributivity of Mul over Add.
func DistributivityTraits[S algebra.HemiRing[E], E algebra.HemiRingElement[E]]() []Trait[S, E] {
	add := func(a, b E) E { return a.Add(b) }
	mul := func(a, b E) E { return a.Mul(b) }
	return []Trait[S, E]{
		&LeftDistributivityTrait[S, E]{Add: add, Mul: mul},
		&RightDistributivityTrait[S, E]{Add: add, Mul: mul},
	}
}

// SemiRingTraits returns traits for testing a semiring.
// A semiring has additive semigroup + multiplicative monoid + distributivity.
// Note: A semiring does NOT require an additive identity (zero).
func SemiRingTraits[S algebra.SemiRing[E], E algebra.SemiRingElement[E]](
	s S,
	mulIsCommutative bool,
) []Trait[S, E] {
	var traits []Trait[S, E]

	// Additive semigroup (addition without requiring zero)
	traits = append(traits, AdditiveSemiGroupTraits[S, E]()...)

	// Multiplicative monoid (multiplication with one)
	traits = append(traits, MultiplicativeMonoidTraits[S, E](s, mulIsCommutative)...)

	// Distributivity
	traits = append(traits, DistributivityTraits[S, E]()...)

	return traits
}

// RingTraits returns traits for testing a ring.
// A ring has additive group + multiplicative monoid + distributivity.
func RingTraits[S algebra.Ring[E], E algebra.RingElement[E]](
	s S,
	mulIsCommutative bool,
) []Trait[S, E] {
	var traits []Trait[S, E]

	// Additive group (addition with zero and negation)
	traits = append(traits, AdditiveGroupTraits[S, E](s)...)

	// Multiplicative monoid (multiplication with one)
	traits = append(traits, MultiplicativeMonoidTraits[S, E](s, mulIsCommutative)...)

	// Distributivity
	traits = append(traits, DistributivityTraits[S, E]()...)

	// Zero annihilation
	traits = append(traits, &ZeroAnnihilationTrait[S, E]{
		Mul:  func(a, b E) E { return a.Mul(b) },
		Zero: func(s S) E { return s.Zero() },
	})

	return traits
}

// FieldTraits returns traits for testing a field.
// A field is a ring where every non-zero element has a multiplicative inverse.
// Note: This requires a generator that produces only non-zero elements for
// the multiplicative inverse tests.
func FieldTraits[S algebra.Field[E], E algebra.FieldElement[E]](
	s S,
) []Trait[S, E] {
	var traits []Trait[S, E]

	// Ring traits (with commutative multiplication)
	traits = append(traits, RingTraits[S, E](s, true)...)

	// Note: Multiplicative inverse requires filtering out zero elements,
	// which needs special handling. For now, we include it in the field test
	// but the generator should exclude zero.

	return traits
}
