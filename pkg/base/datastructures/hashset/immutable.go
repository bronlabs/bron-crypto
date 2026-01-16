package hashset

import (
	"iter"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
)

// ImmutableSet is an immutable wrapper around a MutableSet.
type ImmutableSet[E any] struct {
	v ds.MutableSet[E]
}

// Unfreeze returns a mutable copy of this set.
func (s *ImmutableSet[E]) Unfreeze() ds.MutableSet[E] {
	return s.v.Clone()
}

// Contains returns true if the element is in the set.
func (s *ImmutableSet[E]) Contains(e E) bool {
	return s.v.Contains(e)
}

// Iter returns an iterator over all elements in the set.
func (s *ImmutableSet[E]) Iter() iter.Seq[E] {
	return s.v.Iter()
}

// Iter2 returns an iterator with index and element pairs.
func (s *ImmutableSet[E]) Iter2() iter.Seq2[int, E] {
	return s.v.Iter2()
}

// Size returns the number of elements in the set.
func (s *ImmutableSet[E]) Size() int {
	return s.v.Size()
}

// IsEmpty returns true if the set contains no elements.
func (s *ImmutableSet[E]) IsEmpty() bool {
	return s.v.IsEmpty()
}

// Union returns a new immutable set containing all elements from both sets.
func (s *ImmutableSet[E]) Union(other ds.Set[E]) ds.Set[E] {
	return s.v.Union(other.Unfreeze()).Freeze()
}

// Intersection returns a new immutable set containing only elements present in both sets.
func (s *ImmutableSet[E]) Intersection(other ds.Set[E]) ds.Set[E] {
	return s.v.Intersection(other.Unfreeze()).Freeze()
}

// Difference returns a new immutable set containing elements in this set but not in the other.
func (s *ImmutableSet[E]) Difference(other ds.Set[E]) ds.Set[E] {
	return s.v.Difference(other.Unfreeze()).Freeze()
}

// SymmetricDifference returns a new immutable set containing elements in either set but not both.
func (s *ImmutableSet[E]) SymmetricDifference(other ds.Set[E]) ds.Set[E] {
	return s.v.SymmetricDifference(other.Unfreeze()).Freeze()
}

// SubSets returns all possible subsets of this set (power set).
func (s *ImmutableSet[E]) SubSets() []ds.Set[E] {
	return slices.Collect(
		iterutils.Map(slices.Values(s.v.SubSets()), func(subset ds.MutableSet[E]) ds.Set[E] {
			return subset.Freeze()
		}),
	)
}

// IsSubSet returns true if all elements of this set are in the other set.
func (s *ImmutableSet[E]) IsSubSet(of ds.Set[E]) bool {
	for k := range s.Iter() {
		if !of.Contains(k) {
			return false
		}
	}
	return true
}

// IsProperSubSet returns true if this is a subset of other and they are not equal.
func (s *ImmutableSet[E]) IsProperSubSet(of ds.Set[E]) bool {
	return s.IsSubSet(of) && !s.Equal(of)
}

// IsSuperSet returns true if all elements of the other set are in this set.
func (s *ImmutableSet[E]) IsSuperSet(of ds.Set[E]) bool {
	for k := range of.Iter() {
		if !s.Contains(k) {
			return false
		}
	}
	return true
}

// IsProperSuperSet returns true if this is a superset of other and they are not equal.
func (s *ImmutableSet[E]) IsProperSuperSet(of ds.Set[E]) bool {
	return s.IsSuperSet(of) && !s.Equal(of)
}

// IterSubSets returns an iterator over all possible subsets of this set.
func (s *ImmutableSet[E]) IterSubSets() iter.Seq[ds.Set[E]] {
	return func(yield func(ds.Set[E]) bool) {
		for subset := range s.v.IterSubSets() {
			if !yield(subset.Freeze()) {
				return
			}
		}
	}
}

// List returns a slice of all elements in the set.
func (s *ImmutableSet[E]) List() []E {
	return s.v.List()
}

// Equal returns true if both sets contain exactly the same elements.
func (s *ImmutableSet[E]) Equal(other ds.Set[E]) bool {
	return s.v.Equal(other.Unfreeze())
}

// Clone returns a copy of this set.
func (s *ImmutableSet[E]) Clone() ds.Set[E] {
	return s.v.Freeze()
}

// Cardinality returns the number of elements in the set.
func (s *ImmutableSet[E]) Cardinality() int {
	return s.v.Cardinality()
}
