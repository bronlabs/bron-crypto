package ds_testutils

import (
	// "math/rand"
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

func Battery_Set[S ds.Set[E], E any](t *testing.T,
	setGenerator func(nElements int) *rapid.Generator[S],
) {
	// Inheritance: Set is an AbstractSet
	t.Run("AbstractSet", func(t *testing.T) {
		Battery_AbstractSet(t, setGenerator)
	})

	rapid.Check(t, func(rt *rapid.T) {
		// Input Generation
		emptySet := setGenerator(0).Draw(rt, "EmptySet")
		numElements := rapid.IntRange(1, MaxNumElements).Draw(rt, "numElements")
		B := setGenerator(numElements).Draw(rt, "TestSet")

		t.Run("Size", func(t *testing.T) {
			t.Parallel()
			require.Equal(t, B.Cardinality().Uint64(), uint64(B.Size()), "size and cardinality don't return the same value")
		})

		t.Run("Add", func(t *testing.T) {
			t.Parallel()
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
			t.Parallel()
			A := setGenerator(numElements).Draw(rt, "RemoveSet")
			expectedSize := numElements
			for ai := range A.Iter() {
				A.Remove(ai)
				expectedSize--
				require.False(rt, A.Contains(ai),
					"element %v must not be in the set after removing", ai)
				require.Equal(rt, expectedSize, A.Size(),
					"Size (%v) must be equal to #elements removed (%v)", A.Size(), numElements-expectedSize)
				emptySet.Remove(ai)
				require.Zero(rt, emptySet.Size(), "#A (%d) != 0", emptySet.Size())
			}
			require.Zero(rt, A.Size(), "#A (%d) != 0", A.Size())
		})

		t.Run("Clear", func(t *testing.T) {
			t.Parallel()
			A := setGenerator(numElements).Draw(rt, "RemoveSet")
			A.Clear()
			require.Equal(t, uint64(0), A.Cardinality().Uint64(),
				"Cardinality must be 0 after clearing the set")
			require.True(rt, A.IsEmpty(),
				"Set must be empty after clearing")
		})

		t.Run("IsEmpty", func(t *testing.T) {
			t.Parallel()
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
			t.Parallel()
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
			t.Parallel()
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

		t.Run("Difference", func(t *testing.T) {
			t.Parallel()
			A := setGenerator(numElements).Draw(rt, "DiffrenceSet")

			C := A.Difference(B)

			for ai := range A.Intersection(B).Iter() {
				A.Remove(ai)
			}
			require.Equal(rt, A.Size(), C.Size())

			for ci := range C.Iter() {
				require.True(rt, A.Contains(ci))
			}
		})
		t.Run("SymmetricDifference", func(t *testing.T) {
			t.Parallel()
			A := setGenerator(numElements).Draw(rt, "SymmetricDifferenceSet")

			C := A.SymmetricDifference(B)

			for ci := range C.Iter() {
				require.False(rt, A.Intersection(B).Contains(ci),
					"ci must not be in the intersection of A and B")
			}
		})

		// t.Run("Subset", func(t *testing.T) {
		// 	t.Parallel()
		// 	subsets := B.SubSets()
		// 	num := math.Pow(2, float64(B.Cardinality().Uint64()))

		// 	// Check the number of subsets
		// 	require.Equal(t, subsets, num)

		// 	// // Check if the original set is included in the subsets
		// 	// require.Contains(t, subsets, B)

		// 	// // Check if all subsets are valid
		// 	// for _, subset := range subsets {
		// 	// 	require.True(t, subset.IsSubSet(B),
		// 	//     "subset %v must be a subset of B", subset)
		// 	// }
		// })

		t.Run("IsSubSet", func(t *testing.T) {
			t.Parallel()

			require.True(rt, emptySet.IsSubSet(B),
				"emptySet must be a subset of B")

			require.True(rt, B.IsSubSet(B),
				"B must be a subset of itself")

			subtSets := B.SubSets()
			for subset := range B.IterSubSets() {
				require.Contains(rt, subset, subtSets)
				// for _, subset := range subtSets {
				// 	for ai := range subset.Iter() {
				// 		require.True(rt, B.Contains(ai),
				//         "subset %v must be a subset of B", subset)
				// 	}
			}
		})
		t.Run("IsProperSet", func(t *testing.T) {
			t.Parallel()
			require.True(rt, emptySet.IsProperSubSet(B))
			require.False(rt, B.IsProperSubSet(B))

		})

		t.Run("IsSuperSet", func(t *testing.T) {
			require.True(rt, B.IsSuperSet(emptySet))
			require.True(rt, B.IsSuperSet(B))
			A := setGenerator(MaxNumElements).Draw(rt, "Set A")
			C := A.Intersection(B)

			require.True(rt, B.IsSuperSet(C))
		})
		t.Run("IsProperSuperSet", func(t *testing.T) {
			require.True(rt, B.IsProperSuperSet(emptySet))
			require.False(rt, B.IsProperSuperSet(B))
			A := setGenerator(MaxNumElements).Draw(rt, "Set A")
			C := A.Intersection(B)

			require.True(rt, B.IsSuperSet(C))
		})
		t.Run("IterSubSets", func(t *testing.T) {
			t.Parallel()

			subsets := B.SubSets()

			// for _, subset := range subsets {
			// 	require.True(t, subset.IsSubSet(B),
			// 	"subset %v must be a subset of B", &subset)
			// }
			// for subset := range B.IterSubSets() {
			// 	require.True(rt, B.IsSubSet(subset))
			// }
		})

		t.Run("List", func(t *testing.T) {
			listOfelsemts := B.List()

			for _, el := range listOfelsemts {
				require.True(rt, B.Contains(el))
			}
		})

		t.Run("Clone", func(t *testing.T) {
			A := B.Clone()

			require.Equal(rt, A.Size(), B.Size())
			require.Equal(rt, A.Cardinality().Uint64(), B.Cardinality().Uint64())

			for ai := range A.Iter() {
				require.True(rt, B.Contains(ai))
			}
		})
	})
}
