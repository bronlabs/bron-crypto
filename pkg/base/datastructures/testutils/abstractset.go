package ds_testutils

import (
	"testing"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	tu "github.com/copperexchange/krypton-primitives/pkg/base/testutils2"
	"github.com/stretchr/testify/require"
)

type AbstractSetInvariants[S ds.AbstractSet[E], E any] struct{}

func (asi *AbstractSetInvariants[S, E]) Cardinality(t *testing.T, A S, expectedCardinality int) {
	t.Helper()
	require.NotNil(t, A)
	require.GreaterOrEqual(t, expectedCardinality, 0)
	require.Equal(t, expectedCardinality, int(A.Cardinality().Uint64()),
		"cardinality must match the number of elements in the set")
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
func CheckAbstractSetInvariants[S ds.Set[E], E any](t *testing.T, pt tu.CollectionGenerator[S, E]) {
	t.Helper()
	require.NotNil(t, pt)
	invs := &AbstractSetInvariants[S, E]{}
	t.Run("Cardinality", func(t *testing.T) {
		t.Helper()
		expectedCardinality, err := tu.RandomInt(pt.Prng(), false)
		require.NoError(t, err)
		A := pt.Generate(int(expectedCardinality), true)
		invs.Cardinality(t, A, int(expectedCardinality))
	})
	t.Run("ContainsAndIter", func(t *testing.T) {
		t.Helper()
		expectedCardinality, err := tu.RandomInt(pt.Prng(), false)
		require.NoError(t, err)
		A := pt.Generate(int(expectedCardinality), true)
		invs.ContainsAndIter(t, A, int(expectedCardinality))
	})
}
