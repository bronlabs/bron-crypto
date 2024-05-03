package ds_testutils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	tu "github.com/copperexchange/krypton-primitives/pkg/base/testutils"
)

type SetInvariants[S ds.Set[E], E any] struct {
	EmptySet func() S
}

func (si *SetInvariants[S, E]) Size(t *testing.T, A S, expected int) {
	t.Helper()
	require.NotNil(t, A)
	require.GreaterOrEqual(t, expected, 0)
	cardinality := int(A.Cardinality().Uint64())
	require.Equal(t, cardinality, A.Size(), "size (%d) and cardinality (%d) don't return the same value", A.Size(), cardinality)
	require.Equal(t, expected, A.Size())
}

func (si *SetInvariants[S, E]) Add(t *testing.T, A S, expectedSize int, xs ...E) {
	t.Helper()
	require.NotNil(t, xs)
	require.GreaterOrEqual(t, len(xs), 0)
	for _, x := range xs {
		A.Add(x)
		require.True(t, A.Contains(x), "element %v must be in the set after adding", x)
		A.Add(x) // this is to check whether it impacts the size at the end.
	}
	if len(xs) > 0 {
		require.False(t, A.IsEmpty(), "Set must not be empty after adding elements")
	}
	require.Equal(t, expectedSize, A.Size())
}

func (si *SetInvariants[S, E]) Remove(t *testing.T, A S, expectedSize int, xs ...E) {
	t.Helper()
	require.NotNil(t, A)
	t.Run("can remove all elements of A to get empty set", func(t *testing.T) {
		t.Helper()
		B := A.Clone()
		currentSize := int(B.Cardinality().Uint64())
		for el := range A.Iter() {
			currentSize = int(B.Cardinality().Uint64())

			B.Remove(el)
			require.False(t, B.Contains(el), "element %v must not be in the set after removing", el)
			currentSize--
			require.Equal(t, currentSize, int(B.Cardinality().Uint64()), "Size must decrease when removing element")

			B.Remove(el)
			require.Equal(t, currentSize, int(B.Cardinality().Uint64()), "Size should not change if try remove an element twice")
		}
		require.Zero(t, currentSize, "#B (%d) != 0 after removing all", B.Size())
	})
	t.Run("can remove arbitrarily elements from set correctly", func(t *testing.T) {
		t.Helper()
		B := A.Clone()
		for _, x := range xs {
			currentSize := int(B.Cardinality().Uint64())
			if B.Contains(x) {
				B.Remove(x)
				require.Equal(t, currentSize-1, int(B.Cardinality().Uint64()), "size of B should be updated after removing %v", x)
				require.False(t, B.Contains(x), "element %v should no longer be in B")
			} else {
				B.Remove(x)
				require.Equal(t, currentSize, int(B.Cardinality().Uint64()), "size of B should not change after trying to remove non-member %v", x)
				require.False(t, B.Contains(x), "element %v should still not be in B")
			}
		}
		require.Equal(t, expectedSize, int(B.Cardinality().Uint64()))
	})
}

func (si *SetInvariants[S, E]) Clear(t *testing.T, A S) {
	t.Helper()
	require.NotNil(t, A)

	A.Clear()
	cardinality := int(A.Cardinality().Uint64())
	require.Zero(t, cardinality, "Cardinality must be 0 after clearing the set")
	require.True(t, A.IsEmpty(), "Set must be empty after clearing")
}

func (si *SetInvariants[S, E]) IsEmpty(t *testing.T, A S) {
	t.Helper()
	require.NotNil(t, A)

	cardinality := int(A.Cardinality().Uint64())
	require.Zero(t, cardinality, "Cardinality must be 0 after for an empty set")
	require.True(t, A.IsEmpty(), "Empty set must return true for IsEmpty")
}

func (si *SetInvariants[S, E]) Union(t *testing.T, A, B S) {
	t.Helper()
	require.NotNil(t, A)
	require.NotNil(t, B)

	C := A.Union(B)

	sizeA := int(A.Cardinality().Uint64())
	sizeB := int(B.Cardinality().Uint64())
	sizeC := int(C.Cardinality().Uint64())

	for el := range A.Iter() {
		require.True(t, C.Contains(el), "element %v from A must be in the union", el)
	}
	for el := range B.Iter() {
		require.True(t, C.Contains(el), "element %v from B must be in the union", el)
	}
	elementsInBothSides := 0
	for el := range C.Iter() {
		require.True(t, A.Contains(el) || B.Contains(el), "element %v must be in A or B", el)
		if A.Contains(el) && B.Contains(el) {
			elementsInBothSides++
		}
	}
	require.Equal(t, sizeA+sizeB-elementsInBothSides, sizeC, "Size of union must be equal to the sum of sizes of A and B minus the intersection")
}

func (si *SetInvariants[S, E]) Intersection(t *testing.T, A, B S) {
	t.Helper()
	require.NotNil(t, A)
	require.NotNil(t, B)

	C := A.Intersection(B)
	sizeC := int(C.Cardinality().Uint64())

	for el := range A.Iter() {
		if B.Contains(el) {
			require.True(t, C.Contains(el), "element %v from A, present in B, must be in the intersection", el)
		}
	}
	for el := range B.Iter() {
		if A.Contains(el) {
			require.True(t, C.Contains(el), "element %v from B, present in A, must be in the intersection", el)
		}
	}
	elementsInBothSides := 0
	for el := range C.Iter() {
		require.True(t, A.Contains(el) && B.Contains(el), "element %v must be in both A and B", el)
		elementsInBothSides++
	}
	require.Equal(t, elementsInBothSides, sizeC, "Size of intersection must be equal to the number of elements in both A and B")
}

func (si *SetInvariants[S, E]) Difference(t *testing.T) {
	// TODO
}

func (si *SetInvariants[S, E]) SymmetricDifference(t *testing.T) {
	// TODO
}

func (si *SetInvariants[S, E]) IsSubSet(t *testing.T, A, M S) {
	t.Helper()
	require.NotNil(t, A)
	require.NotNil(t, M)
	wasSubSet := true
	for ai := range A.Iter() {
		if !M.Contains(ai) {
			wasSubSet = false
		}
	}
	require.Equal(t, wasSubSet, A.IsSubSet(M))
}

func (si *SetInvariants[S, E]) IsProperSubSet(t *testing.T) {
	// TODO
}

func (si *SetInvariants[S, E]) IsSuperSet(t *testing.T) {
	// TODO
}

func (si *SetInvariants[S, E]) IsProperSuperSet(t *testing.T) {
	// TODO
}

func (si *SetInvariants[S, E]) IterSubSets(t *testing.T, A S) {
	t.Helper()
	require.NotNil(t, A)

	sizeA := int(A.Cardinality().Uint64())
	totalSubSets := 1 << sizeA

	foundSubSets := 0
	for s := range A.IterSubSets() {
		for si := range s.Iter() {
			require.True(t, A.Contains(si), "element %v from subset is not A", si)
		}
		foundSubSets++
	}
	require.Equal(t, totalSubSets, foundSubSets, "total subsets are many as found subsets")
}

func (si *SetInvariants[S, E]) List(t *testing.T, A S) {
	t.Helper()
	require.NotNil(t, A)
	list := A.List()
	require.Len(t, list, int(A.Cardinality().Uint64()))
	for _, e := range list {
		require.True(t, A.Contains(e))
	}
}

func (si *SetInvariants[S, E]) Clone(t *testing.T) {
	// TODO
}

func CheckSetInvariants[S ds.Set[E], E any](t *testing.T, pt *tu.CollectionPropertyTester[S, E]) {
	t.Helper()
	require.NotNil(t, pt)
	CheckAbstractSetInvariants(t, pt)
	invs := &SetInvariants[S, E]{
		EmptySet: pt.Adapters.Empty,
	}
	t.Run("Size", rapid.MakeCheck(func(rt *rapid.T) {
		numElements := pt.BoundedIntGenerator.Draw(rt, "expected size")
		A := pt.FixedSizeGenerator(numElements).Draw(rt, "Random Set to check its cardinality")
		invs.Size(t, A, numElements)
	}))
	t.Run("Add", rapid.MakeCheck(func(rt *rapid.T) {
		A := pt.VariableSizeGenerator().Draw(rt, "random set to add to")
		xs := pt.VariableSizeElementSliceGenerator(true).Draw(rt, "Random elements to add")

		h := map[uint]any{}
		for _, ai := range pt.Adapters.UnwrapCollection(A) {
			h[ai] = true
		}
		expectedSize := len(h)
		for _, x := range xs {
			if _, exists := h[pt.Adapters.UnwrapElement(x)]; !exists {
				expectedSize++
			}
		}

		invs.Add(t, A, expectedSize, xs...)
	}))
	t.Run("Remove", rapid.MakeCheck(func(rt *rapid.T) {
		A := pt.VariableSizeGenerator().Draw(rt, "random set to remove from")
		xs := pt.VariableSizeElementSliceGenerator(false).Draw(rt, "Random elements to remove")

		h := map[uint]any{}
		for _, ai := range pt.Adapters.UnwrapCollection(A) {
			h[ai] = true
		}
		expectedSize := len(h)
		for _, x := range xs {
			e := pt.Adapters.UnwrapElement(x)
			if _, exists := h[e]; exists {
				expectedSize--
				delete(h, e)
			}
		}

		invs.Remove(t, A, expectedSize, xs...)
	}))
	t.Run("Clear", rapid.MakeCheck(func(rt *rapid.T) {
		A := pt.VariableSizeGenerator().Draw(rt, "random set to clear")
		invs.Clear(t, A)
	}))
	t.Run("IsEmpty", rapid.MakeCheck(func(rt *rapid.T) {
		A := pt.VariableSizeGenerator().Draw(rt, "random set to clear")
		invs.Clear(t, A)
	}))
	t.Run("Union", rapid.MakeCheck(func(rt *rapid.T) {

		pass data here -> A, B 

		A := pt.VariableSizeGenerator().Draw(rt, "lhs of union")
		B := pt.VariableSizeGenerator().Draw(rt, "rhs of union")
		invs.Union(t, A, B)
	}))
	t.Run("Intersection", rapid.MakeCheck(func(rt *rapid.T) {
		A := pt.VariableSizeGenerator().Draw(rt, "lhs of intersection")
		B := pt.VariableSizeGenerator().Draw(rt, "rhs of intersection")
		invs.Intersection(t, A, B)
	}))
	t.Run("IsSubSet", rapid.MakeCheck(func(rt *rapid.T) {
		A := pt.FixedSizeGenerator(3).Draw(rt, "potential subset")
		M := pt.FixedSizeGenerator(5).Draw(rt, "potential superset")
		invs.IsSubSet(t, A, M)
	}))
	t.Run("IterSubSet", rapid.MakeCheck(func(rt *rapid.T) {
		subSetSize := rapid.IntRange(0, 5).Draw(rt, "subset size")
		var A S
		if subSetSize == 0 {
			A = pt.Adapters.Empty()
		} else {
			A = pt.FixedSizeGenerator(subSetSize).Draw(rt, "set to iterate over all of its subsets")
		}
		invs.IterSubSets(t, A)
	}))

}
