package ds_testutils

import (
	"testing"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	fu "github.com/bronlabs/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type AbstractSetInvariants[S ds.AbstractSet[E], E any] struct{}

func (asi *AbstractSetInvariants[S, E]) Cardinality(t *testing.T, A S, expectedCardinality int) {
	t.Helper()
	require.NotNil(t, A)
	require.GreaterOrEqual(t, expectedCardinality, 0)
	require.Equal(t, expectedCardinality, int(A.Cardinality().Uint64()), "cardinality must match the number of elements in the set")
}

func (asi *AbstractSetInvariants[S, E]) ContainsAndIter(t *testing.T, A S, expectedCardinality int) {
	t.Helper()
	require.NotNil(t, A)
	require.GreaterOrEqual(t, expectedCardinality, 0)
	countedElements := 0
	for e := range A.Iter() {
		require.True(t, A.Contains(e), "element %v must be in the set", e)
		countedElements++
	}
	require.Equal(t, expectedCardinality, countedElements, "all elements must be in the set")
}

// type of S is intentional. We don't want other implementations of abstract set like Curves to run these. This choice also makes construction of these sets to depend on List method as opposed to Add whose implementation will have a higher likelihood to contain a bug.
func CheckAbstractSetInvariants[S ds.Set[E], E any](t *testing.T, g fu.CollectionGenerator[S, E]) {
	t.Helper()
	require.NotNil(t, g)
	invs := &AbstractSetInvariants[S, E]{}
	t.Run("Cardinality", func(t *testing.T) {
		t.Helper()
		pt := g.Clone()
		expectedCardinality := pt.Prng().Int(false)
		A := pt.Generate(expectedCardinality, true)
		invs.Cardinality(t, A, expectedCardinality)
	})
	t.Run("ContainsAndIter", func(t *testing.T) {
		t.Helper()
		pt := g.Clone()
		expectedCardinality := pt.Prng().Int(false)
		A := pt.Generate(expectedCardinality, true)
		invs.ContainsAndIter(t, A, expectedCardinality)
	})
}
