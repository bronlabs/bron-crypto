package bitset_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
)

func TestBitSet_AddAndContains(t *testing.T) {
	t.Parallel()

	t.Run("empty set", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		require.False(t, s.Contains(1))
		require.True(t, s.IsEmpty())
		require.Equal(t, 0, s.Size())
	})

	t.Run("add single element", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.Add(1)
		require.True(t, s.Contains(1))
		require.False(t, s.Contains(2))
		require.Equal(t, 1, s.Size())
	})

	t.Run("add multiple elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.Add(1)
		s.Add(5)
		s.Add(10)
		require.True(t, s.Contains(1))
		require.True(t, s.Contains(5))
		require.True(t, s.Contains(10))
		require.False(t, s.Contains(2))
		require.Equal(t, 3, s.Size())
	})

	t.Run("add boundary elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.Add(1)  // minimum
		s.Add(64) // maximum
		require.True(t, s.Contains(1))
		require.True(t, s.Contains(64))
		require.Equal(t, 2, s.Size())
	})

	t.Run("add duplicate element", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.Add(5)
		s.Add(5)
		require.True(t, s.Contains(5))
		require.Equal(t, 1, s.Size())
	})
}

func TestBitSet_AddAll(t *testing.T) {
	t.Parallel()

	t.Run("add multiple at once", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3, 5, 8)
		require.Equal(t, 5, s.Size())
		require.True(t, s.Contains(1))
		require.True(t, s.Contains(2))
		require.True(t, s.Contains(3))
		require.True(t, s.Contains(5))
		require.True(t, s.Contains(8))
	})
}

func TestBitSet_Remove(t *testing.T) {
	t.Parallel()

	t.Run("remove existing element", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		s.Remove(2)
		require.True(t, s.Contains(1))
		require.False(t, s.Contains(2))
		require.True(t, s.Contains(3))
		require.Equal(t, 2, s.Size())
	})

	t.Run("remove non-existing element", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2)
		s.Remove(5)
		require.Equal(t, 2, s.Size())
	})

	t.Run("remove all elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		s.RemoveAll(1, 2, 3)
		require.True(t, s.IsEmpty())
		require.Equal(t, 0, s.Size())
	})
}

func TestBitSet_Clear(t *testing.T) {
	t.Parallel()

	t.Run("clear removes all elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3, 5, 8, 13)
		require.Equal(t, 6, s.Size())

		s.Clear()
		require.True(t, s.IsEmpty())
		require.Equal(t, 0, s.Size())
		require.False(t, s.Contains(1))
	})
}

func TestBitSet_Iter(t *testing.T) {
	t.Parallel()

	t.Run("iterate over elements in order", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(5, 2, 8, 1)

		elements := make([]uint64, 0)
		for e := range s.Iter() {
			elements = append(elements, e)
		}

		// Should be in ascending order: 1, 2, 5, 8
		require.Equal(t, []uint64{1, 2, 5, 8}, elements)
	})

	t.Run("iterate over empty set", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		count := 0
		for range s.Iter() {
			count++
		}
		require.Equal(t, 0, count)
	})
}

func TestBitSet_List(t *testing.T) {
	t.Parallel()

	t.Run("list returns sorted elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(3, 1, 4, 2)

		list := s.List()
		require.Len(t, list, 4)
		require.Equal(t, []uint64{1, 2, 3, 4}, list)
	})
}

func TestBitSet_Clone(t *testing.T) {
	t.Parallel()

	t.Run("clone creates independent copy", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)

		clone := s.Clone()
		require.NotNil(t, clone)
		require.Equal(t, 3, clone.Size())

		// Modify clone
		clone.Add(4)
		require.True(t, clone.Contains(4))
		require.False(t, s.Contains(4))
		require.Equal(t, 3, s.Size())
		require.Equal(t, 4, clone.Size())
	})
}

func TestBitSet_Equal(t *testing.T) {
	t.Parallel()

	t.Run("equal sets regardless of insertion order", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(3, 1, 2)

		require.True(t, s1.Equal(&s2))
		require.True(t, s2.Equal(&s1))

		s2.Add(4)
		require.False(t, s1.Equal(&s2))
	})
}

func TestBitSet_Union(t *testing.T) {
	t.Parallel()

	s1 := bitset.BitSet[uint64](0)
	s1.AddAll(1, 2, 3)

	s2 := bitset.BitSet[uint64](0)
	s2.AddAll(3, 4, 5)

	union := s1.Union(&s2)
	require.Equal(t, 5, union.Size())
	require.True(t, union.Contains(1))
	require.True(t, union.Contains(2))
	require.True(t, union.Contains(3))
	require.True(t, union.Contains(4))
	require.True(t, union.Contains(5))

	// Original sets should not be modified
	require.Equal(t, 3, s1.Size())
	require.Equal(t, 3, s2.Size())
}

func TestBitSet_Intersection(t *testing.T) {
	t.Parallel()

	s1 := bitset.BitSet[uint64](0)
	s1.AddAll(1, 2, 3, 4)

	s2 := bitset.BitSet[uint64](0)
	s2.AddAll(3, 4, 5, 6)

	intersection := s1.Intersection(&s2)
	require.Equal(t, 2, intersection.Size())
	require.True(t, intersection.Contains(3))
	require.True(t, intersection.Contains(4))
	require.False(t, intersection.Contains(1))
	require.False(t, intersection.Contains(5))
}

func TestBitSet_Difference(t *testing.T) {
	t.Parallel()

	s1 := bitset.BitSet[uint64](0)
	s1.AddAll(1, 2, 3, 4)

	s2 := bitset.BitSet[uint64](0)
	s2.AddAll(3, 4, 5)

	diff := s1.Difference(&s2)
	require.Equal(t, 2, diff.Size())
	require.True(t, diff.Contains(1))
	require.True(t, diff.Contains(2))
	require.False(t, diff.Contains(3))
	require.False(t, diff.Contains(4))
}

func TestBitSet_SymmetricDifference(t *testing.T) {
	t.Parallel()

	s1 := bitset.BitSet[uint64](0)
	s1.AddAll(1, 2, 3)

	s2 := bitset.BitSet[uint64](0)
	s2.AddAll(2, 3, 4)

	symDiff := s1.SymmetricDifference(&s2)
	require.Equal(t, 2, symDiff.Size())
	require.True(t, symDiff.Contains(1))
	require.True(t, symDiff.Contains(4))
	require.False(t, symDiff.Contains(2))
	require.False(t, symDiff.Contains(3))
}

func TestBitSet_Freeze(t *testing.T) {
	t.Parallel()

	s := bitset.BitSet[uint64](0)
	s.AddAll(1, 2, 3)

	frozen := s.Freeze()
	require.NotNil(t, frozen)
	require.Equal(t, 3, frozen.Size())
	require.True(t, frozen.Contains(1))
	require.True(t, frozen.Contains(2))
	require.True(t, frozen.Contains(3))

	// Modify original should not affect frozen
	s.Add(4)
	require.False(t, frozen.Contains(4))
	require.Equal(t, 3, frozen.Size())
}

func TestImmutableBitSet_Unfreeze(t *testing.T) {
	t.Parallel()

	s := bitset.BitSet[uint64](0)
	s.AddAll(1, 2, 3)

	frozen := s.Freeze()
	unfrozen := frozen.Unfreeze()

	require.Equal(t, 3, unfrozen.Size())
	unfrozen.Add(4)
	require.Equal(t, 4, unfrozen.Size())

	// Frozen should not be affected
	require.Equal(t, 3, frozen.Size())
	require.False(t, frozen.Contains(4))
}

func TestBitSet_BoundaryValues(t *testing.T) {
	t.Parallel()

	t.Run("element 0 should panic", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		require.Panics(t, func() {
			s.Add(0)
		})
	})

	t.Run("element 65 should panic", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		require.Panics(t, func() {
			s.Add(65)
		})
	})

	t.Run("elements 1-64 should work", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		for i := uint64(1); i <= 64; i++ {
			s.Add(i)
		}
		require.Equal(t, 64, s.Size())
		for i := uint64(1); i <= 64; i++ {
			require.True(t, s.Contains(i))
		}
	})
}

func TestBitSet_Cardinality(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		elements []uint64
		expected int
	}{
		{"empty", []uint64{}, 0},
		{"single", []uint64{5}, 1},
		{"multiple", []uint64{1, 2, 3}, 3},
		{"many", []uint64{1, 10, 20, 30, 40, 50, 60}, 7},
		{"all", []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := bitset.BitSet[uint64](0)
			s.AddAll(tt.elements...)
			require.Equal(t, tt.expected, s.Cardinality())
			require.Equal(t, tt.expected, s.Size())
		})
	}
}

func TestBitSet_Interface(t *testing.T) {
	t.Parallel()

	t.Run("mutable set interface", func(t *testing.T) {
		t.Parallel()
		var _ ds.MutableSet[uint64] = (*bitset.BitSet[uint64])(nil)
	})

	t.Run("immutable set interface", func(t *testing.T) {
		t.Parallel()
		var _ ds.Set[uint64] = (bitset.ImmutableBitSet[uint64])(0)
	})

	t.Run("use as interface", func(t *testing.T) {
		t.Parallel()
		var s ds.MutableSet[uint64] = new(bitset.BitSet[uint64])
		s.Add(1)
		s.Add(2)
		require.Equal(t, 2, s.Size())
		require.True(t, s.Contains(1))
		require.True(t, s.Contains(2))

		frozen := s.Freeze()
		require.Equal(t, 2, frozen.Size())
	})
}

func TestBitSet_IsSubSet(t *testing.T) {
	t.Parallel()

	t.Run("empty set is subset of any set", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3)
		require.True(t, s1.IsSubSet(&s2))
	})

	t.Run("empty set is subset of empty set", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s2 := bitset.BitSet[uint64](0)
		require.True(t, s1.IsSubSet(&s2))
	})

	t.Run("set is subset of itself", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		require.True(t, s.IsSubSet(&s))
	})

	t.Run("proper subset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3, 4)

		require.True(t, s1.IsSubSet(&s2))
		require.False(t, s2.IsSubSet(&s1))
	})

	t.Run("disjoint sets", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(3, 4)

		require.False(t, s1.IsSubSet(&s2))
		require.False(t, s2.IsSubSet(&s1))
	})

	t.Run("overlapping sets", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(2, 3, 4)

		require.False(t, s1.IsSubSet(&s2))
		require.False(t, s2.IsSubSet(&s1))
	})
}

func TestBitSet_IsProperSubSet(t *testing.T) {
	t.Parallel()

	t.Run("proper subset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3)

		require.True(t, s1.IsProperSubSet(&s2))
		require.False(t, s2.IsProperSubSet(&s1))
	})

	t.Run("equal sets are not proper subsets", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3)

		require.False(t, s1.IsProperSubSet(&s2))
		require.False(t, s2.IsProperSubSet(&s1))
	})

	t.Run("empty set is proper subset of non-empty", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2)

		require.True(t, s1.IsProperSubSet(&s2))
		require.False(t, s2.IsProperSubSet(&s1))
	})

	t.Run("empty sets are not proper subsets of each other", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s2 := bitset.BitSet[uint64](0)

		require.False(t, s1.IsProperSubSet(&s2))
	})
}

func TestBitSet_IsSuperSet(t *testing.T) {
	t.Parallel()

	t.Run("any set is superset of empty set", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)

		s2 := bitset.BitSet[uint64](0)

		require.True(t, s1.IsSuperSet(&s2))
	})

	t.Run("set is superset of itself", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		require.True(t, s.IsSuperSet(&s))
	})

	t.Run("proper superset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3, 4)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2)

		require.True(t, s1.IsSuperSet(&s2))
		require.False(t, s2.IsSuperSet(&s1))
	})

	t.Run("disjoint sets", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(3, 4)

		require.False(t, s1.IsSuperSet(&s2))
		require.False(t, s2.IsSuperSet(&s1))
	})
}

func TestBitSet_IsProperSuperSet(t *testing.T) {
	t.Parallel()

	t.Run("proper superset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2)

		require.True(t, s1.IsProperSuperSet(&s2))
		require.False(t, s2.IsProperSuperSet(&s1))
	})

	t.Run("equal sets are not proper supersets", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3)

		require.False(t, s1.IsProperSuperSet(&s2))
	})

	t.Run("non-empty set is proper superset of empty", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)

		s2 := bitset.BitSet[uint64](0)

		require.True(t, s1.IsProperSuperSet(&s2))
		require.False(t, s2.IsProperSuperSet(&s1))
	})
}

func TestBitSet_IterSubSets(t *testing.T) {
	t.Parallel()

	t.Run("empty set has one subset (itself)", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		count := 0
		for subset := range s.IterSubSets() {
			require.Equal(t, 0, subset.Size())
			count++
		}
		require.Equal(t, 1, count)
	})

	t.Run("single element has two subsets", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.Add(5)

		subsets := make([]ds.MutableSet[uint64], 0)
		for subset := range s.IterSubSets() {
			subsets = append(subsets, subset.Clone())
		}

		require.Len(t, subsets, 2) // {} and {5}

		// Find empty and full subsets (order not guaranteed)
		foundEmpty := false
		foundFull := false
		for _, subset := range subsets {
			if subset.Size() == 0 {
				foundEmpty = true
			}
			if subset.Size() == 1 && subset.Contains(5) {
				foundFull = true
			}
		}
		require.True(t, foundEmpty)
		require.True(t, foundFull)
	})

	t.Run("two elements has four subsets", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2)

		subsets := make([]ds.MutableSet[uint64], 0)
		for subset := range s.IterSubSets() {
			subsets = append(subsets, subset.Clone())
		}

		require.Len(t, subsets, 4) // {}, {1}, {2}, {1,2}

		// Verify each subset is actually a subset
		for _, subset := range subsets {
			require.True(t, subset.IsSubSet(&s))
		}
	})

	t.Run("three elements has eight subsets", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)

		count := 0
		for subset := range s.IterSubSets() {
			require.True(t, subset.IsSubSet(&s))
			count++
		}

		require.Equal(t, 8, count) // 2^3 = 8
	})

	t.Run("power set size formula", func(t *testing.T) {
		t.Parallel()
		// Test 2^n formula for various n
		for n := range 7 {
			s := bitset.BitSet[uint64](0)
			for i := 1; i <= n; i++ {
				s.Add(uint64(i))
			}

			count := 0
			for range s.IterSubSets() {
				count++
			}

			expected := 1 << n // 2^n
			require.Equal(t, expected, count, "set of size %d should have %d subsets", n, expected)
		}
	})
}

func TestBitSet_SubSets(t *testing.T) {
	t.Parallel()

	t.Run("subsets of {1,2}", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2)

		subsets := s.SubSets()
		require.Len(t, subsets, 4)

		// Count subsets by size
		sizeCounts := make(map[int]int)
		for _, subset := range subsets {
			sizeCounts[subset.Size()]++
			require.True(t, subset.IsSubSet(&s))
		}

		require.Equal(t, 1, sizeCounts[0]) // {}
		require.Equal(t, 2, sizeCounts[1]) // {1}, {2}
		require.Equal(t, 1, sizeCounts[2]) // {1,2}
	})

	t.Run("subsets of {1,2,3}", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)

		subsets := s.SubSets()
		require.Len(t, subsets, 8)

		// Verify all are valid subsets
		for _, subset := range subsets {
			require.True(t, subset.IsSubSet(&s))
		}
	})

	t.Run("all subsets are different", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3, 4)

		subsets := s.SubSets()
		require.Len(t, subsets, 16)

		// Check all subsets are unique
		for i := range subsets {
			for j := i + 1; j < len(subsets); j++ {
				require.False(t, subsets[i].Equal(subsets[j]),
					"subsets at indices %d and %d should be different", i, j)
			}
		}
	})
}

func TestBitSet_SubSetRelations(t *testing.T) {
	t.Parallel()

	t.Run("subset transitivity", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3)

		s3 := bitset.BitSet[uint64](0)
		s3.AddAll(1, 2, 3, 4)

		// If s1 ⊆ s2 and s2 ⊆ s3, then s1 ⊆ s3
		require.True(t, s1.IsSubSet(&s2))
		require.True(t, s2.IsSubSet(&s3))
		require.True(t, s1.IsSubSet(&s3))
	})

	t.Run("subset and superset are reciprocal", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3)

		require.True(t, s1.IsSubSet(&s2))
		require.True(t, s2.IsSuperSet(&s1))
		require.False(t, s1.IsSuperSet(&s2))
		require.False(t, s2.IsSubSet(&s1))
	})

	t.Run("proper subset implies subset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3)

		if s1.IsProperSubSet(&s2) {
			require.True(t, s1.IsSubSet(&s2))
		}
	})

	t.Run("proper superset implies superset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2)

		if s1.IsProperSuperSet(&s2) {
			require.True(t, s1.IsSuperSet(&s2))
		}
	})
}

func TestBitSet_SubSets_Comprehensive(t *testing.T) {
	t.Parallel()

	t.Run("subsets contain correct elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 3, 5)

		subsets := s.SubSets()
		require.Len(t, subsets, 8)

		// Find specific subsets
		foundEmpty := false
		foundFull := false
		foundSingletons := 0

		for _, subset := range subsets {
			if subset.Size() == 0 {
				foundEmpty = true
			}
			if subset.Size() == 3 {
				foundFull = true
				require.True(t, subset.Contains(1))
				require.True(t, subset.Contains(3))
				require.True(t, subset.Contains(5))
			}
			if subset.Size() == 1 {
				foundSingletons++
				// Should be one of {1}, {3}, or {5}
				require.True(t, subset.Contains(1) || subset.Contains(3) || subset.Contains(5))
			}
		}

		require.True(t, foundEmpty, "should have empty subset")
		require.True(t, foundFull, "should have full set as subset")
		require.Equal(t, 3, foundSingletons, "should have 3 singleton subsets")
	})

	t.Run("larger set subsets", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(2, 4, 6, 8, 10)

		subsets := s.SubSets()
		require.Len(t, subsets, 32) // 2^5

		// Count by cardinality
		sizeCounts := make(map[int]int)
		for _, subset := range subsets {
			sizeCounts[subset.Size()]++
		}

		// Binomial coefficients: C(5,0)=1, C(5,1)=5, C(5,2)=10, C(5,3)=10, C(5,4)=5, C(5,5)=1
		require.Equal(t, 1, sizeCounts[0])
		require.Equal(t, 5, sizeCounts[1])
		require.Equal(t, 10, sizeCounts[2])
		require.Equal(t, 10, sizeCounts[3])
		require.Equal(t, 5, sizeCounts[4])
		require.Equal(t, 1, sizeCounts[5])
	})
}

func TestBitSet_IterSubSets_Properties(t *testing.T) {
	t.Parallel()

	t.Run("can break early", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3, 4)

		count := 0
		for range s.IterSubSets() {
			count++
			if count >= 5 {
				break
			}
		}

		require.Equal(t, 5, count)
	})

	t.Run("all subsets satisfy subset relation", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3, 4, 5)

		for subset := range s.IterSubSets() {
			require.True(t, subset.IsSubSet(&s))
			// Each element in subset should be in s
			for e := range subset.Iter() {
				require.True(t, s.Contains(e))
			}
		}
	})
}

func TestBitSet_SetOperations_WithSubSets(t *testing.T) {
	t.Parallel()

	t.Run("union of subsets", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)

		s1 := bitset.BitSet[uint64](0)
		s1.Add(1)

		s2 := bitset.BitSet[uint64](0)
		s2.Add(2)

		union := s1.Union(&s2)
		require.Equal(t, 2, union.Size())
		require.True(t, union.Contains(1))
		require.True(t, union.Contains(2))

		// Both are subsets of s
		require.True(t, s1.IsSubSet(&s))
		require.True(t, s2.IsSubSet(&s))
		// Their union is also a subset
		require.True(t, union.IsSubSet(&s))
	})

	t.Run("intersection of superset with subset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3, 4)

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(2, 3)

		intersection := s1.Intersection(&s2)
		require.Equal(t, 2, intersection.Size())
		require.True(t, intersection.Equal(&s2))
	})
}

func TestImmutableBitSet_Immutability(t *testing.T) {
	t.Parallel()

	t.Run("freeze creates immutable copy", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)

		frozen := s.Freeze()
		require.Equal(t, 3, frozen.Size())

		// Modify original
		s.Add(4)
		s.Remove(1)

		// Frozen should be unchanged
		require.Equal(t, 3, frozen.Size())
		require.True(t, frozen.Contains(1))
		require.False(t, frozen.Contains(4))
	})

	t.Run("value receiver ensures immutability", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		frozen := s.Freeze()

		// Operations on frozen return new values, don't modify original
		frozen2 := frozen.Union(frozen)
		require.True(t, frozen.Equal(frozen2))
	})

	t.Run("unfreeze creates independent mutable copy", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		frozen := s.Freeze()

		mutable := frozen.Unfreeze()
		mutable.Add(4)

		// Frozen should be unchanged
		require.Equal(t, 3, frozen.Size())
		require.False(t, frozen.Contains(4))
		require.Equal(t, 4, mutable.Size())
	})

	t.Run("clone returns equal value", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(5, 10, 15)
		frozen := s.Freeze()

		clone := frozen.Clone()
		require.True(t, frozen.Equal(clone))
		require.True(t, clone.Equal(frozen))
	})
}

func TestImmutableBitSet_SetOperations(t *testing.T) {
	t.Parallel()

	t.Run("union", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(2, 3)
		frozen2 := s2.Freeze()

		union := frozen1.Union(frozen2)
		require.Equal(t, 3, union.Size())
		require.True(t, union.Contains(1))
		require.True(t, union.Contains(2))
		require.True(t, union.Contains(3))
	})

	t.Run("intersection", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(2, 3, 4)
		frozen2 := s2.Freeze()

		intersection := frozen1.Intersection(frozen2)
		require.Equal(t, 2, intersection.Size())
		require.True(t, intersection.Contains(2))
		require.True(t, intersection.Contains(3))
	})

	t.Run("difference", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3, 4)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(3, 4, 5)
		frozen2 := s2.Freeze()

		diff := frozen1.Difference(frozen2)
		require.Equal(t, 2, diff.Size())
		require.True(t, diff.Contains(1))
		require.True(t, diff.Contains(2))
	})

	t.Run("symmetric difference", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(3, 4, 5)
		frozen2 := s2.Freeze()

		symDiff := frozen1.SymmetricDifference(frozen2)
		require.Equal(t, 4, symDiff.Size())
		require.True(t, symDiff.Contains(1))
		require.True(t, symDiff.Contains(2))
		require.True(t, symDiff.Contains(4))
		require.True(t, symDiff.Contains(5))
		require.False(t, symDiff.Contains(3))
	})
}

func TestImmutableBitSet_SubSetOperations(t *testing.T) {
	t.Parallel()

	t.Run("is subset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3)
		frozen2 := s2.Freeze()

		require.True(t, frozen1.IsSubSet(frozen2))
		require.False(t, frozen2.IsSubSet(frozen1))
	})

	t.Run("is proper subset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2, 3)
		frozen2 := s2.Freeze()

		require.True(t, frozen1.IsProperSubSet(frozen2))
		require.False(t, frozen2.IsProperSubSet(frozen1))

		// Equal sets are not proper subsets
		s3 := bitset.BitSet[uint64](0)
		s3.AddAll(1, 2)
		frozen3 := s3.Freeze()
		require.False(t, frozen1.IsProperSubSet(frozen3))
	})

	t.Run("is superset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2)
		frozen2 := s2.Freeze()

		require.True(t, frozen1.IsSuperSet(frozen2))
		require.False(t, frozen2.IsSuperSet(frozen1))
	})

	t.Run("is proper superset", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(1, 2)
		frozen2 := s2.Freeze()

		require.True(t, frozen1.IsProperSuperSet(frozen2))
		require.False(t, frozen2.IsProperSuperSet(frozen1))
	})
}

func TestImmutableBitSet_SubSets(t *testing.T) {
	t.Parallel()

	t.Run("subsets of frozen set", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		frozen := s.Freeze()

		subsets := frozen.SubSets()
		require.Len(t, subsets, 8)

		for _, subset := range subsets {
			require.True(t, subset.IsSubSet(frozen))
		}
	})

	t.Run("iter subsets", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2)
		frozen := s.Freeze()

		count := 0
		for subset := range frozen.IterSubSets() {
			require.True(t, subset.IsSubSet(frozen))
			count++
		}
		require.Equal(t, 4, count)
	})
}

func TestImmutableBitSet_BasicOperations(t *testing.T) {
	t.Parallel()

	t.Run("contains", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 5, 10)
		frozen := s.Freeze()

		require.True(t, frozen.Contains(1))
		require.True(t, frozen.Contains(5))
		require.True(t, frozen.Contains(10))
		require.False(t, frozen.Contains(2))
	})

	t.Run("size and cardinality", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3, 4, 5)
		frozen := s.Freeze()

		require.Equal(t, 5, frozen.Size())
		require.Equal(t, 5, frozen.Cardinality())
	})

	t.Run("is empty", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		frozen1 := s1.Freeze()
		require.True(t, frozen1.IsEmpty())

		s2 := bitset.BitSet[uint64](0)
		s2.Add(1)
		frozen2 := s2.Freeze()
		require.False(t, frozen2.IsEmpty())
	})

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(3, 1, 4, 2)
		frozen := s.Freeze()

		list := frozen.List()
		require.Equal(t, []uint64{1, 2, 3, 4}, list)
	})

	t.Run("iter", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(2, 4, 6)
		frozen := s.Freeze()

		elements := make([]uint64, 0)
		for e := range frozen.Iter() {
			elements = append(elements, e)
		}
		require.Equal(t, []uint64{2, 4, 6}, elements)
	})

	t.Run("equal", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2, 3)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.AddAll(3, 1, 2)
		frozen2 := s2.Freeze()

		require.True(t, frozen1.Equal(frozen2))
		require.True(t, frozen2.Equal(frozen1))
	})
}

func TestImmutableBitSet_ValueSemantics(t *testing.T) {
	t.Parallel()

	t.Run("assignment creates independent value", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		frozen1 := s.Freeze()

		// Assignment in Go creates a copy for value types
		frozen2 := frozen1
		require.True(t, frozen1.Equal(frozen2))

		// Both should have same underlying value
		require.Equal(t, frozen1.Size(), frozen2.Size())
	})

	t.Run("passing as value parameter", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		frozen := s.Freeze()

		checkSet := func(set ds.Set[uint64]) {
			require.Equal(t, 3, set.Size())
			require.True(t, set.Contains(1))
		}

		checkSet(frozen)
		// After passing, frozen should still be valid
		require.Equal(t, 3, frozen.Size())
	})

	t.Run("operations return new immutable values", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.BitSet[uint64](0)
		s1.AddAll(1, 2)
		frozen1 := s1.Freeze()

		s2 := bitset.BitSet[uint64](0)
		s2.Add(3)
		frozen2 := s2.Freeze()

		union := frozen1.Union(frozen2)
		intersection := frozen1.Intersection(frozen2)
		difference := frozen1.Difference(frozen2)

		// All are distinct values
		require.Equal(t, 3, union.Size())
		require.Equal(t, 0, intersection.Size())
		require.Equal(t, 2, difference.Size())

		// Original frozen sets unchanged
		require.Equal(t, 2, frozen1.Size())
		require.Equal(t, 1, frozen2.Size())
	})
}

func TestImmutableBitSet_TypeAssertion(t *testing.T) {
	t.Parallel()

	t.Run("can type assert to ImmutableBitSet", func(t *testing.T) {
		t.Parallel()
		s := bitset.BitSet[uint64](0)
		s.AddAll(1, 2, 3)
		frozen := s.Freeze()

		immutable, ok := frozen.(bitset.ImmutableBitSet[uint64])
		require.True(t, ok)
		require.Equal(t, uint64(0b111), uint64(immutable)) // bits 0,1,2 set (elements 1,2,3)
	})

	t.Run("direct construction", func(t *testing.T) {
		t.Parallel()
		// Can create ImmutableBitSet directly with correct bit pattern
		// Bit 0 (element 1), bit 1 (element 2), bit 2 (element 3)
		frozen := bitset.ImmutableBitSet[uint64](0b111)
		require.Equal(t, 3, frozen.Size())
		require.True(t, frozen.Contains(1))
		require.True(t, frozen.Contains(2))
		require.True(t, frozen.Contains(3))
	})
}

func TestBitSet_GenericTypes(t *testing.T) {
	t.Parallel()

	t.Run("uint8 elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint8](1, 5, 10)
		require.Equal(t, 3, s.Size())
		require.True(t, s.Contains(1))
		require.True(t, s.Contains(5))
		require.True(t, s.Contains(10))

		// Range is still [1, 64], not [1, 255]
		s.Add(64)
		require.True(t, s.Contains(64))
		require.Equal(t, 4, s.Size())
	})

	t.Run("uint16 elements", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint16](10, 20, 30, 40)
		require.Equal(t, 4, s.Size())

		list := s.List()
		require.Equal(t, []uint16{10, 20, 30, 40}, list)
	})

	t.Run("uint32 elements", func(t *testing.T) {
		t.Parallel()
		s1 := bitset.NewImmutableBitSet[uint32](1, 2, 3)
		s2 := bitset.NewImmutableBitSet[uint32](3, 4, 5)

		union := s1.Union(s2)
		require.Equal(t, 5, union.Size())

		for e := range union.Iter() {
			require.Contains(t, []uint32{1, 2, 3, 4, 5}, e)
		}
	})

	t.Run("operations preserve type", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint16](1, 2, 3)
		clone := s.Clone()

		// Should be able to type assert back
		clonedBitSet, ok := clone.(*bitset.BitSet[uint16])
		require.True(t, ok)
		require.NotNil(t, clonedBitSet)
	})

	t.Run("freeze unfreeze preserves type", func(t *testing.T) {
		t.Parallel()
		s := bitset.NewBitSet[uint32](5, 10, 15)
		frozen := s.Freeze()
		unfrozen := frozen.Unfreeze()

		// Should be able to type assert
		bitsetPtr, ok := unfrozen.(*bitset.BitSet[uint32])
		require.True(t, ok)
		require.Equal(t, 3, bitsetPtr.Size())
	})
}
