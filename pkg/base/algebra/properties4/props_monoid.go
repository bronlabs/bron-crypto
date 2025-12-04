package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// IdentityProperty verifies identity op a = a and a op identity = a.
func IdentityProperty[S algebra.Structure[E], E algebra.Element[E]](
	opName string,
	op func(a, b E) E,
	identity func() E,
) Property[S, E] {
	return Property[S, E]{
		Name: opName + "_Identity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				id := identity()

				// Left identity: identity op a = a
				left := op(id, a)
				require.True(t, left.Equal(a), "left identity failed: identity op a != a")

				// Right identity: a op identity = a
				right := op(a, id)
				require.True(t, right.Equal(a), "right identity failed: a op identity != a")
			})
		},
	}
}

// AdditiveIdentityProperty verifies 0 + a = a and a + 0 = a.
func AdditiveIdentityProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Add_Identity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Add(), "Add operator not defined")
			require.True(t, ctx.HasZero(), "Zero not defined")
			add := ctx.Add().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				zero := ctx.Zero()

				// Left identity: 0 + a = a
				left := add(zero, a)
				require.True(t, left.Equal(a), "left identity failed: 0 + a != a")

				// Right identity: a + 0 = a
				right := add(a, zero)
				require.True(t, right.Equal(a), "right identity failed: a + 0 != a")
			})
		},
	}
}

// MultiplicativeIdentityProperty verifies 1 * a = a and a * 1 = a.
func MultiplicativeIdentityProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Mul_Identity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Mul(), "Mul operator not defined")
			require.True(t, ctx.HasOne(), "One not defined")
			mul := ctx.Mul().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				one := ctx.One()

				// Left identity: 1 * a = a
				left := mul(one, a)
				require.True(t, left.Equal(a), "left identity failed: 1 * a != a")

				// Right identity: a * 1 = a
				right := mul(a, one)
				require.True(t, right.Equal(a), "right identity failed: a * 1 != a")
			})
		},
	}
}

// AdditiveMonoidProperties returns properties for an additive monoid.
func AdditiveMonoidProperties[S algebra.Structure[E], E algebra.Element[E]]() []Property[S, E] {
	props := AdditiveSemiGroupProperties[S, E]()
	props = append(props, AdditiveIdentityProperty[S, E]())
	return props
}

// MultiplicativeMonoidProperties returns properties for a multiplicative monoid.
func MultiplicativeMonoidProperties[S algebra.Structure[E], E algebra.Element[E]](
	commutative bool,
) []Property[S, E] {
	props := MultiplicativeSemiGroupProperties[S, E](commutative)
	props = append(props, MultiplicativeIdentityProperty[S, E]())
	return props
}
