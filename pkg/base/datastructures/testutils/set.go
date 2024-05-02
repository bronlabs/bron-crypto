package ds_testutils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

// SetInvariants implements property-based tests for the Set interface.
type SetInvariants[E any, S ds.Set[E]] struct {
	MaxNumElements uint64 // Maximum number of elements in the generated sets
	Generator      func(nElements uint64) *rapid.Generator[S]
}

func NewSetInvariants[E any, S ds.Set[E]](maxNumElements uint64, generator func(nElements uint64) *rapid.Generator[S]) *SetInvariants[E, S] {
	return &SetInvariants[E, S]{
		MaxNumElements: maxNumElements,
		Generator:      generator,
	}
}

func (si *SetInvariants[E, S]) Check(t *testing.T) {
	// Inherited
	asi := NewAbstractSetInvariants[E, S](si.MaxNumElements, si.Generator)
	asi.Check(t)

	// Local
	rapid.Check(t, si.Size)
	rapid.Check(t, si.Add)
	rapid.Check(t, si.Remove)
	rapid.Check(t, si.Clear)
	rapid.Check(t, si.IsEmpty)
	rapid.Check(t, si.Union)
	rapid.Check(t, si.Intersection)
	rapid.Check(t, si.Difference)
	rapid.Check(t, si.SymmetricDifference)
	rapid.Check(t, si.IsSubSet)
	rapid.Check(t, si.IsProperSubSet)
	rapid.Check(t, si.IsSuperSet)
	rapid.Check(t, si.IsProperSuperSet)
	rapid.Check(t, si.IterSubSets)
	rapid.Check(t, si.List)
	rapid.Check(t, si.Clone)
}

func (si *SetInvariants[E, S]) Size(rt *rapid.T) {
	A := si.generateRandomSet(rt)
	testCardinality := A.Cardinality().Uint64()

	require.Equal(rt, testCardinality, A.Size(),
		"size (%d) and cardinality (%d) don't return the same value", A.Size(), testCardinality)
	require.Equal(rt, 0, si.generateEmptySet(rt).Size(),
		"size must be 0 for an empty set")
}

func (si *SetInvariants[E, S]) Add(rt *rapid.T) {
	A := si.generateRandomSet(rt)
	B := si.generateEmptySet(rt)

	expectedSize := 0
	for el := range A.Iter() {
		B.Add(el)
		require.True(rt, B.Contains(el),
			"element %v must be in the set after adding", el)
		expectedSize++
		require.Equal(rt, expectedSize, B.Size(),
			"Size (%d) must be equal to #elements added (%v)", B.Size(), expectedSize)
		require.False(rt, B.IsEmpty(),
			"Set must not be empty after adding elements")
	}
	require.Equal(rt, A.Size(), B.Size(),
		"Size (%d) of B at the end must be equal to size of A (%d)", B.Size(), A.Size())
}

func (si *SetInvariants[E, S]) Remove(rt *rapid.T) {
	A := si.generateRandomSet(rt)
	B := A.Clone()

	expectedSize := A.Size()
	for el := range A.Iter() {
		B.Remove(el)
		require.False(rt, B.Contains(el),
			"element %v must not be in the set after removing", el)
		expectedSize--
		require.Equal(rt, expectedSize, B.Size(),
			"Size must decrease when removing element")
	}
	require.Zero(rt, B.Size(), "#B (%d) != 0 after removing all", B.Size())
}

func (si *SetInvariants[E, S]) Clear(rt *rapid.T) {
	A := si.generateRandomSet(rt)

	A.Clear()
	require.Equal(rt, 0, int(A.Cardinality().Uint64()),
		"Cardinality must be 0 after clearing the set")
	require.True(rt, A.IsEmpty(),
		"Set must be empty after clearing")
	for range A.Iter() {
		require.Fail(rt, "Iter must be empty after clearing the set")
	}
}

func (si *SetInvariants[E, S]) IsEmpty(rt *rapid.T) {
	A := si.generateEmptySet(rt)

	require.Equal(rt, 0, int(A.Cardinality().Uint64()),
		"Cardinality must be 0 after for an empty set")
	require.True(rt, A.IsEmpty(),
		"Empty set must return true for IsEmpty")
}

func (si *SetInvariants[E, S]) Union(rt *rapid.T) {
	A := si.generateRandomSet(rt)
	B := si.generateRandomSet(rt)
	C := A.Union(B)

	for el := range A.Iter() {
		require.True(rt, C.Contains(el),
			"element %v from A must be in the union", el)
	}
	for el := range B.Iter() {
		require.True(rt, C.Contains(el),
			"element %v from B must be in the union", el)
	}
	elementsInBothSides := 0
	for el := range C.Iter() {
		require.True(rt, A.Contains(el) || B.Contains(el),
			"element %v must be in A or B", el)
		if A.Contains(el) && B.Contains(el) {
			elementsInBothSides++
		}
	}
	require.Equal(rt, A.Size()+B.Size()-elementsInBothSides, C.Size(),
		"Size of union must be equal to the sum of sizes of A and B minus the intersection")
}

func (si *SetInvariants[E, S]) Intersection(rt *rapid.T) {
	A := si.generateRandomSet(rt)
	B := si.generateRandomSet(rt)
	C := A.Intersection(B)

	for el := range A.Iter() {
		if B.Contains(el) {
			require.True(rt, C.Contains(el),
				"element %v from A, present in B, must be in the intersection", el)
		}
	}
	for el := range B.Iter() {
		if A.Contains(el) {
			require.True(rt, C.Contains(el),
				"element %v from B, present in A, must be in the intersection", el)
		}
	}
	elementsInBothSides := 0
	for el := range C.Iter() {
		require.True(rt, A.Contains(el) && B.Contains(el),
			"element %v must be in both A and B", el)
		elementsInBothSides++
	}
	require.Equal(rt, elementsInBothSides, C.Size(),
		"Size of intersection must be equal to the number of elements in both A and B")
}

func (si *SetInvariants[E, S]) Difference(rt *rapid.T) {
	// TODO
}

func (si *SetInvariants[E, S]) SymmetricDifference(rt *rapid.T) {
	// TODO
}

func (si *SetInvariants[E, S]) IsSubSet(rt *rapid.T) {
	// TODO
}

func (si *SetInvariants[E, S]) IsProperSubSet(rt *rapid.T) {
	// TODO
}

func (si *SetInvariants[E, S]) IsSuperSet(rt *rapid.T) {
	// TODO
}

func (si *SetInvariants[E, S]) IsProperSuperSet(rt *rapid.T) {
	// TODO
}

func (si *SetInvariants[E, S]) IterSubSets(rt *rapid.T) {
	// TODO
}

func (si *SetInvariants[E, S]) List(rt *rapid.T) {
	// TODO
}

func (si *SetInvariants[E, S]) Clone(rt *rapid.T) {
	// TODO
}

func (si *SetInvariants[E, S]) generateRandomSet(rt *rapid.T) S {
	nElements := rapid.Uint64Range(1, si.MaxNumElements).Draw(rt, "numElements")
	return si.Generator(nElements).Draw(rt, "TestSet")
}

func (si *SetInvariants[E, S]) generateEmptySet(rt *rapid.T) S {
	return si.Generator(0).Draw(rt, "TestSet")
}
