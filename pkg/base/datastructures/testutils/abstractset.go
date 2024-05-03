package ds_testutils

import (
	"testing"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	tu "github.com/copperexchange/krypton-primitives/pkg/base/testutils"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type AbstractSetInvariants[S ds.AbstractSet[E], E any] struct {
	EmptySet func() S
}

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
func CheckAbstractSetInvariants[S ds.Set[E], E any](t *testing.T, pt *tu.CollectionPropertyTester[S, E]) {
	t.Helper()
	require.NotNil(t, pt)
	invs := &AbstractSetInvariants[S, E]{
		EmptySet: pt.Adapters.Empty,
	}
	t.Run("Cardinality", rapid.MakeCheck(func(rt *rapid.T) {
		expectedCardianlity := pt.BoundedIntGenerator.Draw(rt, "expected cardinality")
		A := pt.FixedSizeGenerator(expectedCardianlity).Draw(rt, "Random Set to check its cardinality")
		invs.Cardinality(t, A, expectedCardianlity)
	}))
	t.Run("ContainsAndIter", rapid.MakeCheck(func(rt *rapid.T) {
		expectedCardinality := pt.BoundedIntGenerator.Draw(rt, "expected cardinality")
		A := pt.FixedSizeGenerator(expectedCardinality).Draw(rt, "Random Set to check its cardinality")
		invs.ContainsAndIter(t, A, expectedCardinality)
	}))
}
