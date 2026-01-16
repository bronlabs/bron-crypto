package hashset_test

import (
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

// Basic Operations

func TestConcurrentSet_AddContains_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		s.Add(elem)

		require.True(t, s.Contains(elem))
	})
}

func TestConcurrentSet_AddAll_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elems := rapid.SliceOf(ElementGenerator()).Draw(t, "elems")

		s.AddAll(elems...)

		for _, e := range elems {
			require.True(t, s.Contains(e))
		}
	})
}

func TestConcurrentSet_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		s.Add(elem)
		require.True(t, s.Contains(elem))

		s.Remove(elem)
		require.False(t, s.Contains(elem))
	})
}

func TestConcurrentSet_RemoveAll_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elems := rapid.SliceOf(ElementGenerator()).Draw(t, "elems")

		s.AddAll(elems...)
		s.RemoveAll(elems...)

		for _, e := range elems {
			require.False(t, s.Contains(e))
		}
	})
}

func TestConcurrentSet_Clear_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")

		s.Clear()

		require.True(t, s.IsEmpty())
		require.Equal(t, 0, s.Size())
	})
}

func TestConcurrentSet_Clone_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")

		cloned := s.Clone()

		require.Equal(t, s.Size(), cloned.Size())
		for e := range s.Iter() {
			require.True(t, cloned.Contains(e))
		}
	})
}

func TestConcurrentSet_Clone_Independence_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		cloned := s.Clone()
		sizeBefore := s.Size()

		// Modify clone
		cloned.Add(elem)

		// Original unchanged if elem was new
		if !s.Contains(elem) {
			require.Equal(t, sizeBefore, s.Size())
		}
	})
}

// Size Properties

func TestConcurrentSet_Size_AddNew_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Filter(func(e string) bool {
			return !s.Contains(e)
		}).Draw(t, "newElem")

		sizeBefore := s.Size()
		s.Add(elem)
		sizeAfter := s.Size()

		require.Equal(t, sizeBefore+1, sizeAfter)
	})
}

func TestConcurrentSet_Size_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := NonEmptyConcurrentSetGenerator().Draw(t, "s")
		list := s.List()
		elem := rapid.SampledFrom(list).Draw(t, "existingElem")

		sizeBefore := s.Size()
		s.Remove(elem)
		sizeAfter := s.Size()

		require.Equal(t, sizeBefore-1, sizeAfter)
	})
}

// Set Operations

func TestConcurrentSet_Union_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ConcurrentSetGenerator().Draw(t, "s1")
		s2 := ImmutableComparableSetGenerator().Draw(t, "s2")

		union := s1.Union(s2)

		for e := range s1.Iter() {
			require.True(t, union.Contains(e))
		}
		for e := range s2.Iter() {
			require.True(t, union.Contains(e))
		}
	})
}

func TestConcurrentSet_Intersection_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ConcurrentSetGenerator().Draw(t, "s1")
		s2 := ImmutableComparableSetGenerator().Draw(t, "s2")

		intersection := s1.Intersection(s2)

		for e := range intersection.Iter() {
			require.True(t, s1.Contains(e))
			require.True(t, s2.Contains(e))
		}
	})
}

func TestConcurrentSet_Difference_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ConcurrentSetGenerator().Draw(t, "s1")
		s2 := ImmutableComparableSetGenerator().Draw(t, "s2")

		diff := s1.Difference(s2)

		for e := range diff.Iter() {
			require.True(t, s1.Contains(e))
			require.False(t, s2.Contains(e))
		}
	})
}

func TestConcurrentSet_SymmetricDifference_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ConcurrentSetGenerator().Draw(t, "s1")
		s2 := ImmutableComparableSetGenerator().Draw(t, "s2")

		symDiff := s1.SymmetricDifference(s2)

		// SymDiff should contain elements in s1 or s2 but not both
		for e := range symDiff.Iter() {
			inS1 := s1.Contains(e)
			inS2 := s2.Contains(e)
			require.True(t, (inS1 || inS2) && !(inS1 && inS2))
		}
	})
}

// Subset Relations

func TestConcurrentSet_IsSubSet_Reflexive_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		frozen := hashset.NewComparable(s.List()...).Freeze()

		require.True(t, s.IsSubSet(frozen))
	})
}

func TestConcurrentSet_IsSubSet_Filtered_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		subset := hashset.NewConcurrentSet(hashset.NewComparable(list[:numToKeep]...))
		superset := hashset.NewComparable(list...).Freeze()

		require.True(t, subset.IsSubSet(superset))
	})
}

func TestConcurrentSet_IsProperSubSet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := NonEmptyConcurrentSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		subset := hashset.NewConcurrentSet(hashset.NewComparable(list[:numToKeep]...))
		superset := hashset.NewComparable(list...).Freeze()

		require.True(t, subset.IsProperSubSet(superset))
		require.Less(t, subset.Size(), superset.Size())
	})
}

func TestConcurrentSet_IsSuperSet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		subset := hashset.NewComparable(list[:numToKeep]...).Freeze()

		require.True(t, s.IsSuperSet(subset))
	})
}

func TestConcurrentSet_IsProperSuperSet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := NonEmptyConcurrentSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		subset := hashset.NewComparable(list[:numToKeep]...).Freeze()

		require.True(t, s.IsProperSuperSet(subset))
		require.Greater(t, s.Size(), subset.Size())
	})
}

// Iteration

func TestConcurrentSet_Iter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")

		visited := make(map[string]bool)
		for e := range s.Iter() {
			visited[e] = true
		}

		require.Equal(t, s.Size(), len(visited))
		for e := range visited {
			require.True(t, s.Contains(e))
		}
	})
}

func TestConcurrentSet_Iter2_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")

		indices := make([]int, 0, s.Size())
		for i := range s.Iter2() {
			indices = append(indices, i)
		}

		require.Equal(t, s.Size(), len(indices))
		slices.Sort(indices)
		for i, idx := range indices {
			require.Equal(t, i, idx)
		}
	})
}

func TestConcurrentSet_List_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")

		list := s.List()

		require.Equal(t, s.Size(), len(list))
		for _, e := range list {
			require.True(t, s.Contains(e))
		}
	})
}

// SubSets

func TestConcurrentSet_SubSets_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := SmallConcurrentSetGenerator().Draw(t, "s")

		subsets := s.SubSets()
		frozen := hashset.NewComparable(s.List()...).Freeze()

		expectedCount := 1 << s.Size()
		require.LessOrEqual(t, len(subsets), expectedCount)

		for _, subset := range subsets {
			require.True(t, subset.IsSubSet(frozen))
		}
	})
}

func TestConcurrentSet_IterSubSets_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := SmallConcurrentSetGenerator().Draw(t, "s")
		frozen := hashset.NewComparable(s.List()...).Freeze()

		count := 0
		for subset := range s.IterSubSets() {
			require.True(t, subset.IsSubSet(frozen))
			count++
		}

		require.LessOrEqual(t, count, 1<<s.Size())
	})
}

// Compute Operations

func TestConcurrentSet_Compute_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		// Remove elem to ensure clean state
		s.Remove(elem)

		// Compute should add elem when shouldStore is true
		result := s.Compute(elem, func(e string, exists bool) (string, bool) {
			require.False(t, exists)
			return e, true
		})

		require.Equal(t, elem, result)
		require.True(t, s.Contains(elem))
	})
}

func TestConcurrentSet_Compute_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		// Add elem first
		s.Add(elem)
		require.True(t, s.Contains(elem))

		// Compute with shouldStore=false should remove
		s.Compute(elem, func(e string, exists bool) (string, bool) {
			require.True(t, exists)
			return e, false
		})

		require.False(t, s.Contains(elem))
	})
}

func TestConcurrentSet_ComputeIfAbsent_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		// Remove elem to ensure it's absent
		s.Remove(elem)

		// ComputeIfAbsent should compute and store when elem is absent
		result := s.ComputeIfAbsent(elem, func(e string) (string, bool) {
			return e, true
		})

		require.Equal(t, elem, result)
		require.True(t, s.Contains(elem))
	})
}

func TestConcurrentSet_ComputeIfAbsent_Exists_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")
		newElem := ElementGenerator().Draw(t, "newElem")

		// Add elem first
		s.Add(elem)

		// ComputeIfAbsent should return existing elem without computing
		computed := false
		result := s.ComputeIfAbsent(elem, func(e string) (string, bool) {
			computed = true
			return newElem, true
		})

		require.False(t, computed)
		require.Equal(t, elem, result)
	})
}

func TestConcurrentSet_ComputeIfPresent_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")
		newElem := ElementGenerator().Draw(t, "newElem")

		// Add elem first
		s.Add(elem)

		// ComputeIfPresent should compute when elem exists
		result := s.ComputeIfPresent(elem, func(e string) (string, bool) {
			require.Equal(t, elem, e)
			return newElem, true
		})

		require.Equal(t, newElem, result)
		require.True(t, s.Contains(newElem))
	})
}

func TestConcurrentSet_ComputeIfPresent_Absent_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		// Remove elem to ensure it's absent
		s.Remove(elem)

		computed := false
		s.ComputeIfPresent(elem, func(e string) (string, bool) {
			computed = true
			return "should-not-store", true
		})

		// Should not compute when elem is absent
		require.False(t, computed)
		require.False(t, s.Contains(elem))
	})
}

// Concurrency Tests

func TestConcurrentSet_ConcurrentAdd_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		inner := hashset.NewComparable[string]()
		s := hashset.NewConcurrentSet(inner)
		elems := rapid.SliceOfN(ElementGenerator(), 10, 100).Draw(t, "elems")

		var wg sync.WaitGroup
		for _, elem := range elems {
			wg.Add(1)
			go func(e string) {
				defer wg.Done()
				s.Add(e)
			}(elem)
		}
		wg.Wait()

		// All unique elements should be present
		uniqueElems := make(map[string]bool)
		for _, e := range elems {
			uniqueElems[e] = true
		}
		require.Equal(t, len(uniqueElems), s.Size())
	})
}

func TestConcurrentSet_ConcurrentAddContains_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		inner := hashset.NewComparable[string]()
		s := hashset.NewConcurrentSet(inner)
		elem := ElementGenerator().Draw(t, "elem")
		numOps := rapid.IntRange(10, 50).Draw(t, "numOps")

		var wg sync.WaitGroup
		for i := 0; i < numOps; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				s.Add(elem)
			}()
			go func() {
				defer wg.Done()
				s.Contains(elem)
			}()
		}
		wg.Wait()

		// Element should be present after all operations
		require.True(t, s.Contains(elem))
	})
}

// Equality

func TestConcurrentSet_Equal_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")
		frozen := hashset.NewComparable(s.List()...).Freeze()

		require.True(t, s.Equal(frozen))
	})
}

// Cardinality

func TestConcurrentSet_Cardinality_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")

		require.Equal(t, s.Size(), s.Cardinality())
	})
}

// IsEmpty

func TestConcurrentSet_IsEmpty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ConcurrentSetGenerator().Draw(t, "s")

		require.Equal(t, s.Size() == 0, s.IsEmpty())
	})
}

// Empty Set

func TestConcurrentSet_Empty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		inner := hashset.NewComparable[string]()
		s := hashset.NewConcurrentSet(inner)

		require.True(t, s.IsEmpty())
		require.Equal(t, 0, s.Size())
		require.Empty(t, s.List())
	})
}
