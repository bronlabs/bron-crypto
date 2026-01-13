package hashset_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// Basic Operations

func TestImmutableSet_Contains_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")
		elem := ElementGenerator().Draw(t, "elem")

		mutable := s.Unfreeze()
		mutable.Add(elem)
		frozen := mutable.Freeze()

		require.True(t, frozen.Contains(elem))
	})
}

func TestImmutableSet_Unfreeze_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")

		unfrozen := s.Unfreeze()

		require.Equal(t, s.Size(), unfrozen.Size())
		for e := range s.Iter() {
			require.True(t, unfrozen.Contains(e))
		}
	})
}

func TestImmutableSet_Clone_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")

		cloned := s.Clone()

		require.Equal(t, s.Size(), cloned.Size())
		for e := range s.Iter() {
			require.True(t, cloned.Contains(e))
		}
	})
}

func TestImmutableSet_Size_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		mutable := MutableComparableSetGenerator().Draw(t, "mutable")
		frozen := mutable.Freeze()

		require.Equal(t, mutable.Size(), frozen.Size())
	})
}

// Set Operations

func TestImmutableSet_Union_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ImmutableComparableSetGenerator().Draw(t, "s1")
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

func TestImmutableSet_Union_Commutative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ImmutableComparableSetGenerator().Draw(t, "s1")
		s2 := ImmutableComparableSetGenerator().Draw(t, "s2")

		union1 := s1.Union(s2)
		union2 := s2.Union(s1)

		require.True(t, union1.Equal(union2))
	})
}

func TestImmutableSet_Intersection_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ImmutableComparableSetGenerator().Draw(t, "s1")
		s2 := ImmutableComparableSetGenerator().Draw(t, "s2")

		intersection := s1.Intersection(s2)

		for e := range intersection.Iter() {
			require.True(t, s1.Contains(e))
			require.True(t, s2.Contains(e))
		}
	})
}

func TestImmutableSet_Intersection_Commutative_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ImmutableComparableSetGenerator().Draw(t, "s1")
		s2 := ImmutableComparableSetGenerator().Draw(t, "s2")

		inter1 := s1.Intersection(s2)
		inter2 := s2.Intersection(s1)

		require.True(t, inter1.Equal(inter2))
	})
}

func TestImmutableSet_Difference_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ImmutableComparableSetGenerator().Draw(t, "s1")
		s2 := ImmutableComparableSetGenerator().Draw(t, "s2")

		diff := s1.Difference(s2)

		for e := range diff.Iter() {
			require.True(t, s1.Contains(e))
			require.False(t, s2.Contains(e))
		}
	})
}

func TestImmutableSet_SymmetricDifference_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ImmutableComparableSetGenerator().Draw(t, "s1")
		s2 := ImmutableComparableSetGenerator().Draw(t, "s2")

		symDiff := s1.SymmetricDifference(s2)
		union := s1.Union(s2)
		intersection := s1.Intersection(s2)
		expected := union.Difference(intersection)

		require.True(t, symDiff.Equal(expected))
	})
}

// Subset Relations

func TestImmutableSet_IsSubSet_Reflexive_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")

		require.True(t, s.IsSubSet(s))
	})
}

func TestImmutableSet_IsSubSet_Filtered_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		mutableSubset := s.Unfreeze()
		mutableSubset.Clear()
		for _, e := range list[:numToKeep] {
			mutableSubset.Add(e)
		}
		subset := mutableSubset.Freeze()

		require.True(t, subset.IsSubSet(s))
	})
}

func TestImmutableSet_IsProperSubSet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		mutableSubset := s.Unfreeze()
		mutableSubset.Clear()
		for _, e := range list[:numToKeep] {
			mutableSubset.Add(e)
		}
		subset := mutableSubset.Freeze()

		require.True(t, subset.IsProperSubSet(s))
		require.Less(t, subset.Size(), s.Size())
	})
}

func TestImmutableSet_IsSuperSet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		mutableSubset := s.Unfreeze()
		mutableSubset.Clear()
		for _, e := range list[:numToKeep] {
			mutableSubset.Add(e)
		}
		subset := mutableSubset.Freeze()

		require.True(t, s.IsSuperSet(subset))
	})
}

func TestImmutableSet_IsProperSuperSet_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")
		list := s.List()
		if len(list) < 2 {
			return
		}
		numToKeep := rapid.IntRange(1, len(list)-1).Draw(t, "numToKeep")
		mutableSubset := s.Unfreeze()
		mutableSubset.Clear()
		for _, e := range list[:numToKeep] {
			mutableSubset.Add(e)
		}
		subset := mutableSubset.Freeze()

		require.True(t, s.IsProperSuperSet(subset))
		require.Greater(t, s.Size(), subset.Size())
	})
}

// Iteration

func TestImmutableSet_Iter_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")

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

func TestImmutableSet_Iter2_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")

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

func TestImmutableSet_List_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")

		list := s.List()

		require.Equal(t, s.Size(), len(list))
		for _, e := range list {
			require.True(t, s.Contains(e))
		}
	})
}

// SubSets

func TestImmutableSet_SubSets_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := SmallImmutableComparableSetGenerator().Draw(t, "s")

		subsets := s.SubSets()

		expectedCount := 1 << s.Size()
		require.LessOrEqual(t, len(subsets), expectedCount)

		for _, subset := range subsets {
			require.True(t, subset.IsSubSet(s))
		}
	})
}

func TestImmutableSet_IterSubSets_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := SmallImmutableComparableSetGenerator().Draw(t, "s")

		count := 0
		for subset := range s.IterSubSets() {
			require.True(t, subset.IsSubSet(s))
			count++
		}

		require.LessOrEqual(t, count, 1<<s.Size())
	})
}

// Equality

func TestImmutableSet_Equal_Reflexive_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")

		require.True(t, s.Equal(s))
	})
}

func TestImmutableSet_Equal_Symmetric_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s1 := ImmutableComparableSetGenerator().Draw(t, "s1")
		s2 := s1.Clone()

		require.True(t, s1.Equal(s2))
		require.True(t, s2.Equal(s1))
	})
}

// Cardinality

func TestImmutableSet_Cardinality_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")

		require.Equal(t, s.Size(), s.Cardinality())
	})
}

// IsEmpty

func TestImmutableSet_IsEmpty_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := ImmutableComparableSetGenerator().Draw(t, "s")

		require.Equal(t, s.Size() == 0, s.IsEmpty())
	})
}
