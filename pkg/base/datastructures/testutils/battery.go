package ds_testutils

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

const MaxNumElements = 100

func Battery_AbstractSet[S ds.AbstractSet[E], E any](t *testing.T,
	abstractSetGenerator func(nElements int) *rapid.Generator[S],
) {
	rapid.Check(t, func(rt *rapid.T) {
		// Input generation
		numElements := rapid.Uint64Range(1, MaxNumElements).Draw(rt, "numElements")
		testSet := abstractSetGenerator(int(numElements)).Draw(rt, "TestAbstractSet")
		emptySet := abstractSetGenerator(0).Draw(rt, "EmptyAbstractSet")

		// Cardinality equal to number of elements in the set
		t.Run("Cardinality", func(t *testing.T) {
			require.Equal(rt, numElements, testSet.Cardinality().Uint64(),
				"Cardinality must be equal to the number of elements in the set")
			require.Equal(rt, uint64(0), emptySet.Cardinality().Uint64(),
				"Cardinality must be 0 for an empty set")
		})

		t.Run("Contains & Iter", func(t *testing.T) {
			for el := range testSet.Iter() {
				require.True(rt, testSet.Contains(el),
					"All elements returned by Iter must be in the set (%v was not)", el)

				require.False(rt, emptySet.Contains(el),
					"No element should be in an empty set")
			}
		})
	})
}

func Battery_Set[E any, S ds.Set[E]](t *testing.T,
	setGenerator func(nElements int) *rapid.Generator[S],
) {
	// Inheritance: Set is an AbstractSet
	t.Run("AbstractSet", func(t *testing.T) {
		Battery_AbstractSet(t, setGenerator)
	})

	rapid.Check(t, func(rt *rapid.T) {
		// Input Generation
		numElements := rapid.IntRange(1, MaxNumElements).Draw(rt, "numElements")
		B := setGenerator(numElements).Draw(rt, "TestSet")

		t.Run("Size", func(t *testing.T) {
			t.Parallel()
			require.Equal(t, B.Cardinality(), B.Size(), "size and cardinality don't return the same value")
		})

		t.Run("Add", func(t *testing.T) {
			A := setGenerator(0).Draw(rt, "AddSet")
			expectedSize := 0
			for bi := range B.Iter() {
				A.Add(bi)
				require.True(rt, A.Contains(bi),
					"element %v must be in the set after adding", bi)
				expectedSize++
				require.Equal(rt, expectedSize, A.Size(),
					"Size (%d) must be equal to #elements added (%v)", A.Size(), expectedSize)
			}
			require.Equal(rt, A.Size(), B.Size(), "Size (%d) of A at the end must be equal to size of B (%d)", A.Size(), B.Size())
		})

		t.Run("Remove", func(t *testing.T) {
			A := setGenerator(numElements).Draw(rt, "RemoveSet")
			expectedSize := numElements
			for ai := range A.Iter() {
				A.Remove(ai)
				expectedSize--
				require.False(rt, A.Contains(ai),
					"element %v must not be in the set after removing", ai)
				require.Equal(rt, expectedSize, A.Size(),
					"Size (%v) must be equal to #elements removed (%v)", A.Size(), numElements-expectedSize)
			}
			require.Zero(rt, A.Size(), "#A (%d) != 0", A.Size())
		})

		t.Run("Clear", func(t *testing.T) {
			A := setGenerator(numElements).Draw(rt, "RemoveSet")
			A.Clear()
			require.Equal(t, uint64(0), A.Cardinality().Uint64(),
				"Cardinality must be 0 after clearing the set")
			require.True(rt, A.IsEmpty(),
				"Set must be empty after clearing")
		})

		t.Run("IsEmpty", func(t *testing.T) {
			emptySet := setGenerator(0).Draw(rt, "EmptySet")
			require.Equal(t, uint64(0), emptySet.Cardinality().Uint64(),
				"Cardinality must be 0 after for an empty set")
			require.True(t, emptySet.IsEmpty())
			for el := range B.Iter() {
				emptySet.Add(el)
				require.True(rt, emptySet.Contains(el),
					"element %v must be in the set after adding", el)
				require.False(t, B.IsEmpty())
			}
		})

		t.Run("Union", func(t *testing.T) {
			A := setGenerator(MaxNumElements).Draw(rt, "Set A")
			B := setGenerator(MaxNumElements).Draw(rt, "Set B")
			C := A.Union(B)

			numElementsFound := 0
			for el := range C.Iter() {
				if A.Contains(el) || B.Contains(el) {
					numElementsFound++
				}
			}
			require.Equal(t, numElementsFound, C.Size())
		})

		t.Run("Intersection", func(t *testing.T) {
			A := setGenerator(MaxNumElements).Draw(rt, "Set A")
			B := setGenerator(0).Draw(rt, "Set B")

			//Randomly adding some elements from A to B
			for el := range A.Iter() {
				rng := rand.Intn(2)
				if rng == 0 {
					B.Add(el)
				}
			}

			C := A.Intersection(B)
			numElementsFound := 0
			for el := range C.Iter() {
				if A.Contains(el) && B.Contains(el) {
					numElementsFound++
				}
			}
			require.Equal(t, numElementsFound, C.Size())
		})
	})
}

// type NewElement[E any] func(x uint) E

// type NewEmptySet[E any] func() ds.Set[E]

// func isInSet[S ds.AbstractSet[E], E any](t *testing.T, s S, e E) {
// 	t.Helper()
// 	require.NotNil(t, s)
// 	require.NotNil(t, e)
// 	s.Contains(e)
// }

// import (
// 	// crand "crypto/rand"
// 	// "io"

// 	"testing"

// 	// "github.com/copperexchange/krypton-primitives/pkg/base/algebra"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/testutils"
// 	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
// 	"github.com/stretchr/testify/require"
// )

// func AbstractSet[S ds.AbstractSet[E], E any](t *testing.T, s S) {
// 	t.Helper()
// 	testutils.Set(t, s, isInSet)
// }

// func Set[S ds.Set[E], E any](t *testing.T, s S, newEmptySet NewEmptySet[E], newElement NewElement[E]) {
// 	t.Helper()
// 	t.Run("AbstractSet", func(t *testing.T) {
// 		t.Parallel()
// 		AbstractSet(t, s)
// 	})
// 	t.Run("Add", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		x0 := newElement(0)
// 		s0.Add(x0)
// 		result := s0.Contains(x0)
// 		require.True(t, result)
// 	})
// 	t.Run("AddAll", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		x0 := newElement(0)
// 		x1 := newElement(1)
// 		x2 := newElement(2)
// 		s0.AddAll(x0, x1, x2)
// 		for _, x := range []E{x0, x1, x2} {
// 			require.True(t, s0.Contains(x))
// 		}
// 	})
// 	t.Run("Remove", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		x0 := newElement(0)
// 		s0.Add(x0)
// 		s0.Remove(x0)
// 		result := s0.Contains(x0)
// 		require.False(t, result)
// 	})
// 	t.Run("Clear", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		s0.Clear()
// 		require.True(t, s0.IsEmpty())
// 	})
// 	t.Run("Size", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		result := s0.Size()
// 		require.Equal(t, 0, result)
// 		x0 := newElement(0)
// 		s0.Add(x0)
// 		result = s0.Size()
// 		require.Equal(t, 1, result)
// 	})
// 	t.Run("IsEmpty", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		require.True(t, s0.IsEmpty())
// 	})
// 	t.Run("Union", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		s1 := newEmptySet()
// 		x0 := newElement(0)
// 		x1 := newElement(1)
// 		s0.Add(x0)
// 		s1.Add(x1)
// 		s2 := s0.Union(s1)
// 		for _, x := range []E{x0, x1} {
// 			result := s2.Contains(x)
// 			require.True(t, result)
// 		}
// 	})
// 	t.Run("Intersection", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		s1 := newEmptySet()
// 		x0 := newElement(0)
// 		x1 := newElement(1)
// 		x2 := newElement(2)
// 		s0.AddAll(x0, x1, x2)
// 		s1.AddAll(x1, x2)
// 		s2 := s0.Intersection(s1)
// 		for _, x := range []E{x1, x2} {
// 			result := s2.Contains(x)
// 			require.True(t, result)
// 		}
// 	})
// 	t.Run("Difference", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		s1 := newEmptySet()
// 		x0 := newElement(0)
// 		x1 := newElement(1)
// 		x2 := newElement(2)
// 		s0.AddAll(x0, x1, x2)
// 		s1.AddAll(x1, x2)
// 		s2 := s0.Difference(s1)
// 		for _, x := range []E{x0} {
// 			result := s2.Contains(x)
// 			require.True(t, result)
// 		}
// 	})
// 	t.Run("SymetricDifference", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		s1 := newEmptySet()
// 		x0 := newElement(0)
// 		x1 := newElement(1)
// 		x2 := newElement(2)
// 		s0.AddAll(x0, x1, x2)
// 		s1.AddAll(x1, x2)
// 		s2 := s0.SymmetricDifference(s1)
// 		for _, x := range []E{x0} {
// 			result := s2.Contains(x)
// 			require.True(t, result)
// 		}
// 	})
// 	t.Run("SubSets", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		s0.AddAll(newElement(0), newElement(1), newElement(2))

// 		subsets := s0.SubSets()

// 		// Check the number of subsets
// 		require.Len(t, subsets, 8)

// 		// Check if the original set is included in the subsets
// 		require.Contains(t, subsets, s0)

// 		// Check if all subsets are valid
// 		for _, subset := range subsets {
// 			require.True(t, subset.IsSubSet(s0))
// 		}
// 	})
// 	t.Run("IsSubSet", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		x0 := newElement(0)
// 		x1 := newElement(1)
// 		x2 := newElement(2)
// 		s0.AddAll(x0, x1, x2)
// 		subsets := s0.SubSets()
// 		require.Len(t, subsets, 8)
// 		require.Contains(t, subsets, s0)
// 		for _, subset := range subsets {
// 			require.True(t, subset.IsSubSet(s0))
// 		}
// 	})
// 	t.Run("IsProperSubSet", func(t *testing.T) {
// 		A := newEmptySet()
// 		A.Add(newElement(0))
// 		A.Add(newElement(1))
// 		A.Add(newElement(2))

// 		B := newEmptySet()
// 		B.Add(newElement(0))
// 		B.Add(newElement(1))

// 		C := newEmptySet()
// 		C.Add(newElement(0))
// 		C.Add(newElement(1))

// 		require.True(t, B.IsProperSubSet(A))
// 		require.True(t, C.IsProperSubSet(A))
// 		require.False(t, C.IsProperSubSet(B))
// 	})
// 	t.Run("IsSuperSet", func(t *testing.T) {
// 		t.Parallel()

// 		A := newEmptySet()
// 		A.Add(newElement(0))
// 		A.Add(newElement(1))
// 		A.Add(newElement(2))

// 		B := newEmptySet()
// 		B.Add(newElement(0))
// 		B.Add(newElement(1))

// 		C := newEmptySet()
// 		C.Add(newElement(0))
// 		C.Add(newElement(1))
// 		C.Add(newElement(2))
// 		C.Add(newElement(3))

// 		D := newEmptySet()
// 		D.Add(newElement(0))
// 		D.Add(newElement(2))

// 		require.True(t, A.IsSuperSet(B))
// 		require.False(t, B.IsSuperSet(A))
// 		require.False(t, A.IsSuperSet(C))
// 		require.True(t, C.IsSuperSet(A))
// 		require.True(t, A.IsSuperSet(D))
// 		require.False(t, D.IsSuperSet(A))
// 	})
// 	t.Run("IsProperSuperSet", func(t *testing.T) {
// 		t.Parallel()

// 		A := newEmptySet()
// 		A.Add(newElement(123))
// 		A.Add(newElement(456))
// 		A.Add(newElement(789))

// 		B := newEmptySet()
// 		B.Add(newElement(123))
// 		B.Add(newElement(456))

// 		C := newEmptySet()
// 		C.Add(newElement(123))
// 		C.Add(newElement(456))

// 		require.True(t, B.IsProperSubSet(A))
// 		require.True(t, C.IsProperSubSet(A))
// 		require.False(t, C.IsProperSubSet(B))
// 	})
// 	t.Run("IterSubSets", func(t *testing.T) {
// 		t.Parallel()
// 		s0 := newEmptySet()
// 		s0.AddAll(newElement(0), newElement(1), newElement(2))

// 		//all subsets of s0
// 		sub1 := newEmptySet()
// 		sub1.AddAll(newElement(0))

// 		sub2 := newEmptySet()
// 		sub2.AddAll(newElement(1))

// 		sub3 := newEmptySet()
// 		sub3.AddAll(newElement(2))

// 		sub4 := newEmptySet()
// 		sub4.AddAll(newElement(0), newElement(1))

// 		sub5 := newEmptySet()
// 		sub5.AddAll(newElement(0), newElement(2))

// 		sub6 := newEmptySet()
// 		sub6.AddAll(newElement(1), newElement(2))

// 		sub7 := newEmptySet()
// 		sub7.AddAll(newElement(0), newElement(1), newElement(2))

// 		sub8 := newEmptySet()

// 		expectedSubsets := []ds.Set[E]{sub1, sub2, sub3, sub4, sub5, sub6, sub7, sub8}

// 		for subset := range s0.IterSubSets() {
// 			// check subset contains of the above subsets (order is not guarantee)
// 			found := false
// 			for _, expected := range expectedSubsets {
// 				if subset.Equal(expected) {
// 					found = true
// 					break
// 				}
// 			}
// 			require.True(t, found)
// 		}
// 	})
// 	t.Run("List", func(t *testing.T) {
// 		t.Parallel()

// 		A := newEmptySet()
// 		A.AddAll(newElement(123), newElement(456))

// 		B := A.List()

// 		require.Len(t, B, 2)

// 		for _, x := range B {
// 			require.True(t, A.Contains(x))
// 		}
// 	})
// 	t.Run("Clone", func(t *testing.T) {
// 		t.Parallel()
// 		A := newEmptySet()
// 		A.Add(newElement(123))
// 		A.Add(newElement(456))
// 		A.Add(newElement(789))

// 		B := A.Clone()
// 		C := A.Intersection(B)
// 		require.Equal(t, C, B)
// 	})
// }
