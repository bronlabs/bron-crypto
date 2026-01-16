package hashset_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

// Basic Operations

func TestComparableSet_AddContains_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		s.Add(elem)

		require.True(t, s.Contains(elem))
	})
}

func TestComparableSet_AddAll_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")
		elems := rapid.SliceOf(ElementGenerator()).Draw(t, "elems")

		s.AddAll(elems...)

		for _, e := range elems {
			require.True(t, s.Contains(e))
		}
	})
}

func TestComparableSet_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		s.Add(elem)
		require.True(t, s.Contains(elem))

		s.Remove(elem)
		require.False(t, s.Contains(elem))
	})
}

func TestComparableSet_RemoveAll_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")
		elems := rapid.SliceOf(ElementGenerator()).Draw(t, "elems")

		s.AddAll(elems...)
		s.RemoveAll(elems...)

		for _, e := range elems {
			require.False(t, s.Contains(e))
		}
	})
}

func TestComparableSet_Clear_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

		s.Clear()

		require.True(t, s.IsEmpty())
		require.Equal(t, 0, s.Size())
	})
}

func TestComparableSet_Clone_Equality_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

		cloned := s.Clone()

		require.Equal(t, s.Size(), cloned.Size())
		for e := range s.Iter() {
			require.True(t, cloned.Contains(e))
		}
	})
}

func TestComparableSet_Clone_Independence_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")
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

func TestComparableSet_Size_AddNew_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Filter(func(e string) bool {
			return !s.Contains(e)
		}).Draw(t, "newElem")

		sizeBefore := s.Size()
		s.Add(elem)
		sizeAfter := s.Size()

		require.Equal(t, sizeBefore+1, sizeAfter)
	})
}

func TestComparableSet_Size_AddExisting_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := NonEmptyMutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		elem := rapid.SampledFrom(list).Draw(t, "existingElem")

		sizeBefore := s.Size()
		s.Add(elem)
		sizeAfter := s.Size()

		require.Equal(t, sizeBefore, sizeAfter)
	})
}

func TestComparableSet_Size_Remove_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := NonEmptyMutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		elem := rapid.SampledFrom(list).Draw(t, "existingElem")

		sizeBefore := s.Size()
		s.Remove(elem)
		sizeAfter := s.Size()

		require.Equal(t, sizeBefore-1, sizeAfter)
	})
}

// Set Operations

func TestComparableSet_Union_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := MutableComparableSetGenerator().Draw(t, "s1")
		s2 := MutableComparableSetGenerator().Draw(t, "s2")

		union := s1.Union(s2)

		// Union contains all elements from s1
		for e := range s1.Iter() {
			require.True(t, union.Contains(e))
		}
		// Union contains all elements from s2
		for e := range s2.Iter() {
			require.True(t, union.Contains(e))
		}
	})
}

func TestComparableSet_Union_Commutative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := MutableComparableSetGenerator().Draw(t, "s1")
		s2 := MutableComparableSetGenerator().Draw(t, "s2")

		union1 := s1.Union(s2)
		union2 := s2.Union(s1)

		require.True(t, union1.Equal(union2))
	})
}

func TestComparableSet_Intersection_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := MutableComparableSetGenerator().Draw(t, "s1")
		s2 := MutableComparableSetGenerator().Draw(t, "s2")

		intersection := s1.Intersection(s2)

		// Intersection only contains common elements
		for e := range intersection.Iter() {
			require.True(t, s1.Contains(e))
			require.True(t, s2.Contains(e))
		}
	})
}

func TestComparableSet_Intersection_Commutative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := MutableComparableSetGenerator().Draw(t, "s1")
		s2 := MutableComparableSetGenerator().Draw(t, "s2")

		inter1 := s1.Intersection(s2)
		inter2 := s2.Intersection(s1)

		require.True(t, inter1.Equal(inter2))
	})
}

func TestComparableSet_Difference_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := MutableComparableSetGenerator().Draw(t, "s1")
		s2 := MutableComparableSetGenerator().Draw(t, "s2")

		diff := s1.Difference(s2)

		// Diff contains elements from s1 not in s2
		for e := range diff.Iter() {
			require.True(t, s1.Contains(e))
			require.False(t, s2.Contains(e))
		}
	})
}

func TestComparableSet_SymmetricDifference_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := MutableComparableSetGenerator().Draw(t, "s1")
		s2 := MutableComparableSetGenerator().Draw(t, "s2")

		symDiff := s1.SymmetricDifference(s2)
		union := s1.Union(s2)
		intersection := s1.Intersection(s2)
		expected := union.Difference(intersection)

		require.True(t, symDiff.Equal(expected))
	})
}

// Subset Relations

func TestComparableSet_IsSubSet_Reflexive_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

		require.True(t, s.IsSubSet(s))
	})
}

func TestComparableSet_IsSubSet_Empty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")
		empty := hashset.NewComparable[string]()

		require.True(t, empty.IsSubSet(s))
	})
}

func TestComparableSet_IsSubSet_Filtered_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		subset := hashset.NewComparable(list[:numToKeep]...)

		require.True(t, subset.IsSubSet(s))
	})
}

func TestComparableSet_IsProperSubSet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := NonEmptyMutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		subset := hashset.NewComparable(list[:numToKeep]...)

		require.True(t, subset.IsProperSubSet(s))
		require.Less(t, subset.Size(), s.Size())
	})
}

func TestComparableSet_IsSuperSet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		subset := hashset.NewComparable(list[:numToKeep]...)

		require.True(t, s.IsSuperSet(subset))
	})
}

func TestComparableSet_IsProperSuperSet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := NonEmptyMutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		subset := hashset.NewComparable(list[:numToKeep]...)

		require.True(t, s.IsProperSuperSet(subset))
		require.Greater(t, s.Size(), subset.Size())
	})
}

// Freeze/Unfreeze

func TestComparableSet_Freeze_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

		frozen := s.Freeze()

		require.Equal(t, s.Size(), frozen.Size())
		for e := range s.Iter() {
			require.True(t, frozen.Contains(e))
		}
	})
}

func TestComparableSet_FreezeUnfreeze_Roundtrip_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

		frozen := s.Freeze()
		unfrozen := frozen.Unfreeze()

		require.Equal(t, s.Size(), unfrozen.Size())
		for e := range s.Iter() {
			require.True(t, unfrozen.Contains(e))
		}
	})
}

// Iteration

func TestComparableSet_Iter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

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

func TestComparableSet_Iter2_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

		indices := make([]int, 0, s.Size())
		elements := make(map[string]bool)
		for i, e := range s.Iter2() {
			indices = append(indices, i)
			elements[e] = true
		}

		require.Equal(t, s.Size(), len(indices))
		slices.Sort(indices)
		for i, idx := range indices {
			require.Equal(t, i, idx)
		}
	})
}

func TestComparableSet_List_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

		list := s.List()

		require.Equal(t, s.Size(), len(list))
		for _, e := range list {
			require.True(t, s.Contains(e))
		}
	})
}

// SubSets (small sets only due to exponential complexity)

func TestComparableSet_SubSets_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := SmallMutableComparableSetGenerator().Draw(t, "s")

		subsets := s.SubSets()

		// SubSets count is 2^n
		expectedCount := 1 << s.Size()
		require.Equal(t, expectedCount, len(subsets))

		// Each subset should be a subset of s
		for _, subset := range subsets {
			require.True(t, subset.IsSubSet(s))
		}
	})
}

func TestComparableSet_IterSubSets_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := SmallMutableComparableSetGenerator().Draw(t, "s")

		count := 0
		for subset := range s.IterSubSets() {
			require.True(t, subset.IsSubSet(s))
			count++
		}

		// Should yield proper subsets (excluding full set based on implementation)
		require.LessOrEqual(t, count, 1<<s.Size())
	})
}

// Equality

func TestComparableSet_Equal_Reflexive_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

		require.True(t, s.Equal(s))
	})
}

func TestComparableSet_Equal_Symmetric_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := MutableComparableSetGenerator().Draw(t, "s1")
		s2 := s1.Clone()

		require.True(t, s1.Equal(s2))
		require.True(t, s2.Equal(s1))
	})
}

// Cardinality

func TestComparableSet_Cardinality_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := MutableComparableSetGenerator().Draw(t, "s")

		require.Equal(t, s.Size(), s.Cardinality())
	})
}
