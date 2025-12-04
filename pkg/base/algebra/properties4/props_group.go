package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// InverseProperty verifies a op inv(a) = identity and inv(a) op a = identity.
func InverseProperty[S algebra.Structure[E], E algebra.Element[E]](
	opName string,
	op func(a, b E) E,
	inv func(a E) E,
	identity func() E,
) Property[S, E] {
	return Property[S, E]{
		Name: opName + "_Inverse",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				id := identity()
				invA := inv(a)

				// Right inverse: a op inv(a) = identity
				right := op(a, invA)
				require.True(t, right.Equal(id), "right inverse failed: a op inv(a) != identity")

				// Left inverse: inv(a) op a = identity
				left := op(invA, a)
				require.True(t, left.Equal(id), "left inverse failed: inv(a) op a != identity")
			})
		},
	}
}

// AdditiveInverseProperty verifies a + (-a) = 0 and (-a) + a = 0.
func AdditiveInverseProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Add_Inverse",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Add(), "Add operator not defined")
			require.True(t, ctx.HasZero(), "Zero not defined")
			require.True(t, ctx.HasNeg(), "Neg not defined")
			add := ctx.Add().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				zero := ctx.Zero()
				negA := ctx.Neg(a)

				// Right inverse: a + (-a) = 0
				right := add(a, negA)
				require.True(t, right.Equal(zero), "right inverse failed: a + (-a) != 0")

				// Left inverse: (-a) + a = 0
				left := add(negA, a)
				require.True(t, left.Equal(zero), "left inverse failed: (-a) + a != 0")
			})
		},
	}
}

// MultiplicativeInverseProperty verifies a * a^-1 = 1 and a^-1 * a = 1.
// Note: This assumes the generator produces only non-zero elements.
func MultiplicativeInverseProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Mul_Inverse",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Mul(), "Mul operator not defined")
			require.True(t, ctx.HasOne(), "One not defined")
			require.True(t, ctx.HasInv(), "Inv not defined")
			mul := ctx.Mul().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				one := ctx.One()
				invA := ctx.Inv(a)

				// Right inverse: a * a^-1 = 1
				right := mul(a, invA)
				require.True(t, right.Equal(one), "right inverse failed: a * a^-1 != 1")

				// Left inverse: a^-1 * a = 1
				left := mul(invA, a)
				require.True(t, left.Equal(one), "left inverse failed: a^-1 * a != 1")
			})
		},
	}
}

// AdditiveGroupProperties returns properties for an additive group.
func AdditiveGroupProperties[S algebra.Structure[E], E algebra.Element[E]]() []Property[S, E] {
	props := AdditiveMonoidProperties[S, E]()
	props = append(props, AdditiveInverseProperty[S, E]())
	return props
}

// MultiplicativeGroupProperties returns properties for a multiplicative group.
// Note: This assumes all elements have inverses (e.g., non-zero field elements).
func MultiplicativeGroupProperties[S algebra.Structure[E], E algebra.Element[E]](
	commutative bool,
) []Property[S, E] {
	props := MultiplicativeMonoidProperties[S, E](commutative)
	props = append(props, MultiplicativeInverseProperty[S, E]())
	return props
}
