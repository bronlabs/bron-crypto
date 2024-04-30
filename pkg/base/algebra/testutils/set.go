package testutils

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

func Set[S algebra.Set[E], E algebra.Element](t *testing.T, s S, isMember IsElement[S, E]) {
	t.Helper()
	t.Run("Iter", func(t *testing.T) {
		t.Parallel()
		i := 0
		for e := range s.Iter() {
			if i >= propertyCheckLimit {
				return
			}
			isMember(t, s, e)
			i++
		}
	})
	t.Run("Cardinality", func(t *testing.T) {
		t.Parallel()
		c := s.Cardinality()
		require.NotNil(t, c)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			cc := s.Cardinality()
			require.Equal(t, c.Nat().Eq(cc.Nat()), saferith.Choice(1))

		})
	})
	t.Run("Contains", func(t *testing.T) {
		t.Parallel()
		var el E
		for e := range s.Iter() {
			el = e
			break
		}
		require.True(t, s.Contains(el))
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			require.True(t, s.Contains(el))
			require.True(t, s.Contains(el))
		})
	})
}

func SetElement[S algebra.Set[E], E algebra.Element](t *testing.T, s S, e E) {
	t.Helper()
	require.NotNil(t, s)
	require.NotNil(t, e)
	require.True(t, s.Contains(e))
}

func IsSet[S algebra.Set[E], E algebra.Element](t *testing.T, s S) {
	t.Helper()
	Set(t, s, SetElement)
}

func StructuredSet[S algebra.StructuredSet[S, E], E algebra.StructuredSetElement[S, E]](t *testing.T, s S, isMember IsElement[S, E]) {
	t.Helper()
	t.Run("Set", func(t *testing.T) {
		t.Parallel()
		Set(t, s, isMember)
	})
	t.Run("Random", func(t *testing.T) {
		for i := range propertyCheckLimit {
			e, err := s.Random(crand.Reader)
			require.NoError(t, err, "iteration %d", i)
			isMember(t, s, e)
		}
		t.Run("cannot accept nil", func(t *testing.T) {
			t.Parallel()
			_, err := s.Random(nil)
			require.Error(t, err)
		})
	})
	t.Run("Element", func(t *testing.T) {
		e := s.Element()
		isMember(t, s, e)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			ee := s.Element()
			require.True(t, e.Equal(ee))
		})
	})
	t.Run("Name", func(t *testing.T) {
		n := s.Name()
		require.Greater(t, len(n), 0)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			require.Equal(t, n, s.Name())
		})
	})
	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		o := s.Order()
		require.NotNil(t, o)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			oo := s.Order()
			require.Equal(t, o.Nat().Eq(oo.Nat()), saferith.Choice(1))

		})
		t.Run("is the same as cardinality", func(t *testing.T) {
			t.Parallel()
			c := s.Cardinality()
			require.Equal(t, o.Nat().Eq(c.Nat()), saferith.Choice(1))
		})
	})
	t.Run("Operators", func(t *testing.T) {
		t.Parallel()
		os := s.Operators()
		require.GreaterOrEqual(t, os, 1)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			os2 := s.Operators()
			require.EqualValues(t, os2, os)
		})
	})
	t.Run("Unwrap", func(t *testing.T) {
		t.Parallel()
		out := s.Unwrap()
		require.NotNil(t, out)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			out2 := s.Unwrap()
			require.Equal(t, out2, out)
		})
	})
	t.Run("Conditionally Selectable", func(t *testing.T) {
		t.Parallel()
		for range propertyCheckLimit {
			x0, err := s.Random(crand.Reader)
			require.NoError(t, err)
			x1, err := s.Random(crand.Reader)
			require.NoError(t, err)
			ConditionallySelectable[E](t, s, x0, x1)
		}
	})
}

func StructuredSetElement[S algebra.StructuredSet[S, E], E algebra.StructuredSetElement[S, E]](t *testing.T, s S, e E) {
	t.Helper()
	t.Run("Set Element", func(t *testing.T) {
		t.Parallel()
		SetElement(t, s, e)
	})
	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		s := e.Structure()
		require.NotNil(t, s)
		s.Contains(e)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			ss := e.Structure()
			require.Equal(t, s, ss)
		})

	})
	t.Run("Unwrap", func(t *testing.T) {
		t.Parallel()
		out := e.Unwrap()
		require.NotNil(t, out)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			out2 := e.Unwrap()
			require.Equal(t, out2, out)
		})
	})
	t.Run("Clone", func(t *testing.T) {
		t.Parallel()
		ee := e.Clone()
		require.True(t, e.Equal(ee), "value equality")
		// TODO: figure out how
		// require.NotEqual(t, &e, &ee, "reference inequality")
	})
	t.Run("Hashable", func(t *testing.T) {
		t.Skip()
		// TODO: add this.
	})
}

func IsStructuredSet[S algebra.StructuredSet[S, E], E algebra.StructuredSetElement[S, E]](t *testing.T, s S) {
	t.Helper()
	StructuredSet(t, s, StructuredSetElement)
}

func FiniteStructure[S algebra.FiniteStructure[S, E], E algebra.StructuredSetElement[S, E]](t *testing.T, s S, isMember IsElement[S, E]) {
	t.Helper()
	t.Run("Structured Set", func(t *testing.T) {
		t.Parallel()
		StructuredSet(t, s, isMember)
	})
	t.Run("Hash", func(t *testing.T) {
		x1 := make([]byte, 54)
		x2 := make([]byte, 17)
		for _, x := range [][]byte{x1, x2} {
			_, err := io.ReadFull(crand.Reader, x)
			require.NoError(t, err)
		}
		x1h, err := s.Hash(x1)
		require.NoError(t, err)
		x2h, err := s.Hash(x2)
		require.NoError(t, err)
		t.Run("hashing to the same structure", func(t *testing.T) {
			t.Parallel()
			isMember(t, s, x1h)
			isMember(t, s, x2h)
		})
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			x1h2, err := s.Hash(x1)
			require.NoError(t, err)
			require.True(t, x1h.Equal(x1h2))
		})
		t.Run("can accept empty", func(t *testing.T) {
			t.Parallel()
			empty1 := make([]byte, 0)
			empty2 := make([]byte, 10)
			e1, err := s.Hash(empty1)
			require.NoError(t, err)
			e2, err := s.Hash(empty2)
			require.NoError(t, err)

			require.True(t, e1.Equal(e2))
			isMember(t, s, e1)
		})
		t.Run("cannot accept nil", func(t *testing.T) {
			t.Parallel()
			_, err := s.Hash(nil)
			require.Error(t, err)
		})
	})
	t.Run("ElementSize", func(t *testing.T) {
		t.Parallel()
		x := s.ElementSize()
		require.Positive(t, x)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			xx := s.ElementSize()
			require.Equal(t, xx, x)
		})
	})
	t.Run("WideElementSize", func(t *testing.T) {
		t.Parallel()
		x := s.WideElementSize()
		require.Positive(t, x)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			xx := s.WideElementSize()
			require.Equal(t, xx, x)
		})
		t.Run("is greater than ElementSize", func(t *testing.T) {
			xx := s.ElementSize()
			require.Greater(t, xx, x)
		})
	})
}

func IsFiniteStructure[S algebra.FiniteStructure[S, E], E algebra.StructuredSetElement[S, E]](t *testing.T, s S) {
	t.Helper()
	FiniteStructure(t, s, StructuredSetElement)
}

func PointedSet[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]](t *testing.T, s S, isMember IsElement[S, E]) {
	t.Helper()
	t.Run("Structured Set", func(t *testing.T) {
		t.Parallel()
		StructuredSet(t, s, isMember)
	})
	t.Run("BasePoint", func(t *testing.T) {
		t.Parallel()
		x := s.BasePoint()
		isMember(t, s, x)
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			xx := s.BasePoint()
			require.True(t, x.Equal(xx))
		})
	})
}

func PointedSetElement[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]](t *testing.T, s S, e E) {
	t.Helper()
	t.Run("Structured Set Element", func(t *testing.T) {
		t.Parallel()
		StructuredSetElement(t, s, e)
	})
	t.Run("IsBasePoint", func(t *testing.T) {
		t.Parallel()
		x := s.BasePoint()
		require.True(t, x.IsBasePoint())
		t.Run("is idempotent", func(t *testing.T) {
			t.Parallel()
			require.True(t, x.IsBasePoint())
			require.True(t, x.IsBasePoint())
		})
	})
}
func IsPointedSet[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]](t *testing.T, s S) {
	t.Helper()
	PointedSet(t, s, PointedSetElement)
}
