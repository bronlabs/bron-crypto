package properties

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func NewStructuralPropertySuite[S algebra.Structure[E], E algebra.Element[E]](t *testing.T, s S, g *rapid.Generator[E]) *Structural[S, E] {
	t.Helper()
	require.NotNil(t, g, "generator must not be nil")
	return &Structural[S, E]{
		st: s,
		g:  g,
	}
}

type Structural[S algebra.Structure[E], E algebra.Element[E]] struct {
	st S
	g  *rapid.Generator[E]
}

func (e *Structural[S, E]) CheckAll(t *testing.T) {
	t.Helper()
	t.Run("HashCodeEqualityCorrespondence", e.HashCodeEqualityCorrespondence)
	t.Run("CanEquate", e.CanEquate)
}

func (e *Structural[S, E]) HashCodeEqualityCorrespondence(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := e.g.Draw(t, "a")
		b := e.g.Draw(t, "b")
		require.Equal(t, a.Equal(b), a.HashCode() == b.HashCode())
	})
}

func (e *Structural[S, E]) CanEquate(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := e.g.Draw(t, "a")
		b := e.g.Draw(t, "b")
		c := e.g.Draw(t, "c")

		// Reflexive
		require.True(t, a.Equal(a))

		// Symmetric
		if a.Equal(b) {
			require.True(t, b.Equal(a))
		}

		// Transitive
		if a.Equal(b) && b.Equal(c) {
			require.True(t, a.Equal(c))
		}
	})
}
