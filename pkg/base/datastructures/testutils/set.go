package testutils

import (
	// crand "crypto/rand"
	// "io"
	"testing"

	// "github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/testutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/stretchr/testify/require"
)

type NewElement[E any] func(x uint) E
type NewEmptySet[E any] func() ds.Set[E]

func isInSet[S ds.AbstractSet[E], E any](t *testing.T, s S, e E) {
	t.Helper()
	require.NotNil(t, s)
	require.NotNil(t, e)
	s.Contains(e)
}

func AbstractSet[S ds.AbstractSet[E], E any](t *testing.T, s S) {
	t.Helper()
	testutils.Set(t, s, isInSet)
}

func Set[S ds.Set[E], E any](t *testing.T, s S, newEmptySet NewEmptySet[E], newElement NewElement[E]) {
	t.Helper()
	t.Run("AbstractSet", func(t *testing.T) {
		t.Parallel()
		AbstractSet(t, s)
	})
	t.Run("Add", func(t *testing.T) {
		t.Parallel()
		s0 := newEmptySet()
		x0 := newElement(0)
		s0.Add(x0)
		s0.Contains(x0)
	})
}
