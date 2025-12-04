package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// LeftDistributivityProperty verifies a * (b + c) = (a * b) + (a * c).
func LeftDistributivityProperty[S algebra.Structure[E], E algebra.Element[E]](
	add func(a, b E) E,
	mul func(a, b E) E,
) Property[S, E] {
	return Property[S, E]{
		Name: "Mul_LeftDistributesOver_Add",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := ctx.Draw(rt, "c")

				// a * (b + c)
				left := mul(a, add(b, c))
				// (a * b) + (a * c)
				right := add(mul(a, b), mul(a, c))

				require.True(t, left.Equal(right), "left distributivity failed: a * (b + c) != (a * b) + (a * c)")
			})
		},
	}
}

// RightDistributivityProperty verifies (a + b) * c = (a * c) + (b * c).
func RightDistributivityProperty[S algebra.Structure[E], E algebra.Element[E]](
	add func(a, b E) E,
	mul func(a, b E) E,
) Property[S, E] {
	return Property[S, E]{
		Name: "Mul_RightDistributesOver_Add",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := ctx.Draw(rt, "c")

				// (a + b) * c
				left := mul(add(a, b), c)
				// (a * c) + (b * c)
				right := add(mul(a, c), mul(b, c))

				require.True(t, left.Equal(right), "right distributivity failed: (a + b) * c != (a * c) + (b * c)")
			})
		},
	}
}

// DistributivityProperty verifies a * (b + c) = (a * b) + (a * c) using context operators.
func DistributivityProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Mul_DistributesOver_Add",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Add(), "Add operator not defined")
			require.NotNil(t, ctx.Mul(), "Mul operator not defined")
			add := ctx.Add().Apply
			mul := ctx.Mul().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := ctx.Draw(rt, "c")

				// Left distributivity: a * (b + c) = (a * b) + (a * c)
				leftD := mul(a, add(b, c))
				rightD := add(mul(a, b), mul(a, c))
				require.True(t, leftD.Equal(rightD), "left distributivity failed: a * (b + c) != (a * b) + (a * c)")

				// Right distributivity: (a + b) * c = (a * c) + (b * c)
				leftD2 := mul(add(a, b), c)
				rightD2 := add(mul(a, c), mul(b, c))
				require.True(t, leftD2.Equal(rightD2), "right distributivity failed: (a + b) * c != (a * c) + (b * c)")
			})
		},
	}
}

// ZeroAnnihilationProperty verifies 0 * a = 0 and a * 0 = 0.
func ZeroAnnihilationProperty[S algebra.Structure[E], E algebra.Element[E]](
	mul func(a, b E) E,
	zero func() E,
) Property[S, E] {
	return Property[S, E]{
		Name: "Mul_ZeroAnnihilation",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				z := zero()

				// 0 * a = 0
				left := mul(z, a)
				require.True(t, left.Equal(z), "left zero annihilation failed: 0 * a != 0")

				// a * 0 = 0
				right := mul(a, z)
				require.True(t, right.Equal(z), "right zero annihilation failed: a * 0 != 0")
			})
		},
	}
}

// ZeroAnnihilationPropertyCtx verifies 0 * a = 0 and a * 0 = 0 using context operators.
func ZeroAnnihilationPropertyCtx[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Mul_ZeroAnnihilation",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Mul(), "Mul operator not defined")
			require.True(t, ctx.HasZero(), "Zero not defined")
			mul := ctx.Mul().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				zero := ctx.Zero()

				// 0 * a = 0
				left := mul(zero, a)
				require.True(t, left.Equal(zero), "left zero annihilation failed: 0 * a != 0")

				// a * 0 = 0
				right := mul(a, zero)
				require.True(t, right.Equal(zero), "right zero annihilation failed: a * 0 != 0")
			})
		},
	}
}

// DistributivityProperties returns distributivity properties using context operators.
func DistributivityProperties[S algebra.Structure[E], E algebra.Element[E]]() []Property[S, E] {
	return []Property[S, E]{
		DistributivityProperty[S, E](),
	}
}

// SemiRingProperties returns properties for a semiring (additive semigroup + multiplicative monoid + distributivity).
func SemiRingProperties[S algebra.Structure[E], E algebra.Element[E]](
	mulCommutative bool,
) []Property[S, E] {
	var props []Property[S, E]

	// Additive semigroup
	props = append(props, AdditiveSemiGroupProperties[S, E]()...)

	// Multiplicative monoid
	props = append(props, MultiplicativeMonoidProperties[S, E](mulCommutative)...)

	// Distributivity
	props = append(props, DistributivityProperties[S, E]()...)

	return props
}

// RingProperties returns properties for a ring (additive group + multiplicative monoid + distributivity + zero annihilation).
func RingProperties[S algebra.Structure[E], E algebra.Element[E]](
	mulCommutative bool,
) []Property[S, E] {
	var props []Property[S, E]

	// Additive group
	props = append(props, AdditiveGroupProperties[S, E]()...)

	// Multiplicative monoid
	props = append(props, MultiplicativeMonoidProperties[S, E](mulCommutative)...)

	// Distributivity
	props = append(props, DistributivityProperties[S, E]()...)

	// Zero annihilation
	props = append(props, ZeroAnnihilationPropertyCtx[S, E]())

	return props
}

// FieldProperties returns properties for a field (ring with multiplicative inverses for non-zero elements).
// Note: This assumes the generator produces only non-zero elements for multiplicative inverse tests.
func FieldProperties[S algebra.Structure[E], E algebra.Element[E]]() []Property[S, E] {
	var props []Property[S, E]

	// Ring with commutative multiplication
	props = append(props, RingProperties[S, E](true)...)

	// Multiplicative inverse (requires non-zero elements)
	// Note: The generator should exclude zero for this to work correctly.

	return props
}
