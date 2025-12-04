package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// ReflexivityProperty verifies that a.Equal(a) is always true.
func ReflexivityProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Reflexivity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				require.True(t, a.Equal(a), "reflexivity failed: a.Equal(a) should be true")
			})
		},
	}
}

// SymmetryProperty verifies that a.Equal(b) implies b.Equal(a).
func SymmetryProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Symmetry",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				if a.Equal(b) {
					require.True(t, b.Equal(a), "symmetry failed: a.Equal(b) but not b.Equal(a)")
				}
			})
		},
	}
}

// TransitivityProperty verifies that a.Equal(b) && b.Equal(c) implies a.Equal(c).
func TransitivityProperty[S algebra.Structure[E], E algebra.Element[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Transitivity",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Draw(rt, "b")
				c := ctx.Draw(rt, "c")
				if a.Equal(b) && b.Equal(c) {
					require.True(t, a.Equal(c), "transitivity failed: a.Equal(b) && b.Equal(c) but not a.Equal(c)")
				}
			})
		},
	}
}

// EqualityProperties returns all equality relation properties.
func EqualityProperties[S algebra.Structure[E], E algebra.Element[E]]() []Property[S, E] {
	return []Property[S, E]{
		ReflexivityProperty[S, E](),
		SymmetryProperty[S, E](),
		TransitivityProperty[S, E](),
	}
}
