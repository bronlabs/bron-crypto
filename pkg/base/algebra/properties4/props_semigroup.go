package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// ClosureProperty verifies that applying an operation produces a non-nil result.
func ClosureProperty[S algebra.Structure[E], E algebra.Element[E]](
	opName string,
	op func(a, b E) E,
) Property[S, E] {
	return Property[S, E]{
		Name: opName + "_Closure",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := op(a, b)
				require.NotNil(t, c, "closure failed: operation should return non-nil result")
			})
		},
	}
}

// AssociativityProperty verifies (a op b) op c = a op (b op c).
func AssociativityProperty[S algebra.Structure[E], E algebra.Element[E]](
	opName string,
	op func(a, b E) E,
) Property[S, E] {
	return Property[S, E]{
		Name: opName + "_Associativity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := ctx.Draw(rt, "c")
				left := op(op(a, b), c)
				right := op(a, op(b, c))
				require.True(t, left.Equal(right), "associativity failed: (a op b) op c != a op (b op c)")
			})
		},
	}
}

// CommutativityProperty verifies a op b = b op a.
func CommutativityProperty[S algebra.Structure[E], E algebra.Element[E]](
	opName string,
	op func(a, b E) E,
) Property[S, E] {
	return Property[S, E]{
		Name: opName + "_Commutativity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				left := op(a, b)
				right := op(b, a)
				require.True(t, left.Equal(right), "commutativity failed: a op b != b op a")
			})
		},
	}
}

// AdditionClosureProperty verifies addition closure using the context's Add operator.
func AdditionClosureProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Add_Closure",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Add(), "Add operator not defined")
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := ctx.Add().Apply(a, b)
				require.NotNil(t, c, "closure failed: Add should return non-nil result")
			})
		},
	}
}

// AdditionAssociativityProperty verifies (a + b) + c = a + (b + c).
func AdditionAssociativityProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Add_Associativity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Add(), "Add operator not defined")
			add := ctx.Add().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := ctx.Draw(rt, "c")
				left := add(add(a, b), c)
				right := add(a, add(b, c))
				require.True(t, left.Equal(right), "associativity failed: (a + b) + c != a + (b + c)")
			})
		},
	}
}

// AdditionCommutativityProperty verifies a + b = b + a.
func AdditionCommutativityProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Add_Commutativity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Add(), "Add operator not defined")
			add := ctx.Add().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				left := add(a, b)
				right := add(b, a)
				require.True(t, left.Equal(right), "commutativity failed: a + b != b + a")
			})
		},
	}
}

// MultiplicationClosureProperty verifies multiplication closure using the context's Mul operator.
func MultiplicationClosureProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Mul_Closure",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Mul(), "Mul operator not defined")
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := ctx.Mul().Apply(a, b)
				require.NotNil(t, c, "closure failed: Mul should return non-nil result")
			})
		},
	}
}

// MultiplicationAssociativityProperty verifies (a * b) * c = a * (b * c).
func MultiplicationAssociativityProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Mul_Associativity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Mul(), "Mul operator not defined")
			mul := ctx.Mul().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := ctx.Draw(rt, "c")
				left := mul(mul(a, b), c)
				right := mul(a, mul(b, c))
				require.True(t, left.Equal(right), "associativity failed: (a * b) * c != a * (b * c)")
			})
		},
	}
}

// MultiplicationCommutativityProperty verifies a * b = b * a.
func MultiplicationCommutativityProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Mul_Commutativity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.NotNil(t, ctx.Mul(), "Mul operator not defined")
			mul := ctx.Mul().Apply
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				left := mul(a, b)
				right := mul(b, a)
				require.True(t, left.Equal(right), "commutativity failed: a * b != b * a")
			})
		},
	}
}

// AdditiveSemiGroupProperties returns properties for an additive semigroup.
func AdditiveSemiGroupProperties[S algebra.Structure[E], E algebra.Element[E]]() []Property[S, E] {
	return []Property[S, E]{
		AdditionClosureProperty[S, E](),
		AdditionAssociativityProperty[S, E](),
		AdditionCommutativityProperty[S, E](),
	}
}

// MultiplicativeSemiGroupProperties returns properties for a multiplicative semigroup.
func MultiplicativeSemiGroupProperties[S algebra.Structure[E], E algebra.Element[E]](
	commutative bool,
) []Property[S, E] {
	props := []Property[S, E]{
		MultiplicationClosureProperty[S, E](),
		MultiplicationAssociativityProperty[S, E](),
	}
	if commutative {
		props = append(props, MultiplicationCommutativityProperty[S, E]())
	}
	return props
}
