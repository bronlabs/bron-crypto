package hashset

import (
	"iter"
	"maps"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type comparableMapping[K comparable] = map[K]struct{}

// NewComparable creates a new mutable set for comparable element types.
func NewComparable[E comparable](xs ...E) ds.MutableSet[E] {
	s := &MutableComparableSet[E]{v: make(comparableMapping[E])}
	for _, x := range xs {
		s.v[x] = struct{}{}
	}
	return s
}

// MutableComparableSet is a mutable hash set for comparable element types.
type MutableComparableSet[E comparable] struct {
	v comparableMapping[E]
}

// Add adds an element to the set.
func (s *MutableComparableSet[E]) Add(e E) {
	s.v[e] = struct{}{}
}

// AddAll adds multiple elements to the set.
func (s *MutableComparableSet[E]) AddAll(es ...E) {
	for _, e := range es {
		s.v[e] = struct{}{}
	}
}

// Remove removes an element from the set.
func (s *MutableComparableSet[E]) Remove(e E) {
	delete(s.v, e)
}

// RemoveAll removes multiple elements from the set.
func (s *MutableComparableSet[E]) RemoveAll(es ...E) {
	for _, e := range es {
		delete(s.v, e)
	}
}

// Freeze returns an immutable snapshot of this set.
func (s *MutableComparableSet[E]) Freeze() ds.Set[E] {
	return &ImmutableSet[E]{v: &MutableComparableSet[E]{v: maps.Clone(s.v)}}
}

// Clear removes all elements from the set.
func (s *MutableComparableSet[E]) Clear() {
	clear(s.v)
}

// Contains returns true if the element is in the set.
func (s *MutableComparableSet[E]) Contains(e E) bool {
	_, exists := s.v[e]
	return exists
}

// Clone returns a mutable copy of this set.
func (s *MutableComparableSet[E]) Clone() ds.MutableSet[E] {
	return &MutableComparableSet[E]{v: maps.Clone(s.v)}
}

// Equal returns true if both sets contain exactly the same elements.
func (s *MutableComparableSet[E]) Equal(other ds.MutableSet[E]) bool {
	return s.IsSubSet(other) && other.IsSubSet(s)
}

// Size returns the number of elements in the set.
func (s *MutableComparableSet[_]) Size() int {
	return len(s.v)
}

// Cardinality returns the number of elements in the set.
func (s *MutableComparableSet[_]) Cardinality() int {
	return len(s.v)
}

// IsEmpty returns true if the set contains no elements.
func (s *MutableComparableSet[_]) IsEmpty() bool {
	return len(s.v) == 0
}

// Union returns a new set containing all elements from both sets.
func (s *MutableComparableSet[E]) Union(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := s.Clone()
	out.AddAll(other.List()...)
	return out
}

// Intersection returns a new set containing only elements present in both sets.
func (s *MutableComparableSet[E]) Intersection(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := &MutableComparableSet[E]{v: make(comparableMapping[E])}
	for k := range s.Iter() {
		if other.Contains(k) {
			out.v[k] = struct{}{}
		}
	}
	return out
}

// Difference returns a new set containing elements in this set but not in the other.
func (s *MutableComparableSet[E]) Difference(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := s.Clone()
	out.RemoveAll(other.List()...)
	return out
}

// SymmetricDifference returns a new set containing elements in either set but not both.
func (s *MutableComparableSet[E]) SymmetricDifference(other ds.MutableSet[E]) ds.MutableSet[E] {
	return s.Union(other).Difference(s.Intersection(other))
}

// SubSets returns all possible subsets of this set (power set).
func (s *MutableComparableSet[E]) SubSets() []ds.MutableSet[E] {
	result := make([]ds.MutableSet[E], 1<<s.Size())
	i := 0
	for subset := range s.IterSubSets() {
		result[i] = subset
		i++
	}
	return result
}

// Iter returns an iterator over all elements in the set.
func (s *MutableComparableSet[E]) Iter() iter.Seq[E] {
	return func(yield func(E) bool) {
		for el := range s.v {
			if !yield(el) {
				return
			}
		}
	}
}

// Iter2 returns an iterator with index and element pairs.
func (s *MutableComparableSet[E]) Iter2() iter.Seq2[int, E] {
	return func(yield func(int, E) bool) {
		i := 0
		for el := range s.v {
			if !yield(i, el) {
				return
			}
			i++
		}
	}
}

// IsSubSet returns true if all elements of this set are in the other set.
func (s *MutableComparableSet[E]) IsSubSet(of ds.MutableSet[E]) bool {
	for k := range s.Iter() {
		if !of.Contains(k) {
			return false
		}
	}
	return true
}

// IsProperSubSet returns true if this is a subset of other and they are not equal.
func (s *MutableComparableSet[E]) IsProperSubSet(of ds.MutableSet[E]) bool {
	return s.IsSubSet(of) && !s.Equal(of)
}

// IsSuperSet returns true if all elements of the other set are in this set.
func (s *MutableComparableSet[E]) IsSuperSet(of ds.MutableSet[E]) bool {
	for k := range of.Iter() {
		if _, exists := s.v[k]; !exists {
			return false
		}
	}
	return true
}

// IsProperSuperSet returns true if this is a superset of other and they are not equal.
func (s *MutableComparableSet[E]) IsProperSuperSet(of ds.MutableSet[E]) bool {
	return s.IsSuperSet(of) && !s.Equal(of)
}

// IterSubSets returns an iterator over all possible subsets of this set.
func (s *MutableComparableSet[E]) IterSubSets() iter.Seq[ds.MutableSet[E]] {
	return func(yield func(ds.MutableSet[E]) bool) {
		list := s.List()
		for i := 0; i <= s.Size(); i++ {
			for comb := range sliceutils.Combinations(list, uint(i)) {
				subset := NewComparable(comb...)
				if !yield(subset) {
					return
				}
			}
		}
	}
}

// List returns a slice of all elements in the set.
func (s *MutableComparableSet[E]) List() []E {
	return slices.AppendSeq(make([]E, 0, len(s.v)), maps.Keys(s.v))
}
