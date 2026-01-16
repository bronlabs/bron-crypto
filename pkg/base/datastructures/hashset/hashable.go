package hashset

import (
	"iter"

	base "github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

// NewHashable creates a new mutable set for hashable element types.
func NewHashable[E ds.Hashable[E]](xs ...E) ds.MutableSet[E] {
	s := &MutableHashableSet[E]{v: hashmap.NewHashable[E, struct{}]()}
	for _, x := range xs {
		s.v.Put(x, struct{}{})
	}
	return s
}

// MutableHashableSet is a mutable hash set for hashable element types.
type MutableHashableSet[E ds.Hashable[E]] struct {
	v ds.MutableMap[E, struct{}]
}

// Add adds an element to the set.
func (s *MutableHashableSet[E]) Add(e E) {
	s.v.Put(e, struct{}{})
}

// AddAll adds multiple elements to the set.
func (s *MutableHashableSet[E]) AddAll(es ...E) {
	for _, e := range es {
		s.v.Put(e, struct{}{})
	}
}

// Remove removes an element from the set.
func (s *MutableHashableSet[E]) Remove(e E) {
	s.v.Remove(e)
}

// RemoveAll removes multiple elements from the set.
func (s *MutableHashableSet[E]) RemoveAll(es ...E) {
	for _, e := range es {
		s.v.Remove(e)
	}
}

// Freeze returns an immutable snapshot of this set.
func (s *MutableHashableSet[E]) Freeze() ds.Set[E] {
	return &ImmutableSet[E]{v: &MutableHashableSet[E]{v: s.v.Clone()}}
}

// Clone returns a mutable copy of this set.
func (s *MutableHashableSet[E]) Clone() ds.MutableSet[E] {
	return &MutableHashableSet[E]{v: s.v.Clone()}
}

// Clear removes all elements from the set.
func (s *MutableHashableSet[E]) Clear() {
	s.v.Clear()
}

// Contains returns true if the element is in the set.
func (s *MutableHashableSet[E]) Contains(e E) bool {
	return s.v.ContainsKey(e)
}

// Equal returns true if both sets contain exactly the same elements.
func (s *MutableHashableSet[E]) Equal(other ds.MutableSet[E]) bool {
	return s.IsSubSet(other) && other.IsSubSet(s)
}

// Size returns the number of elements in the set.
func (s *MutableHashableSet[_]) Size() int {
	return s.v.Size()
}

// Cardinality returns the number of elements in the set.
func (s *MutableHashableSet[_]) Cardinality() int {
	return s.v.Size()
}

// IsEmpty returns true if the set contains no elements.
func (s *MutableHashableSet[_]) IsEmpty() bool {
	return s.Size() == 0
}

// Union returns a new set containing all elements from both sets.
func (s *MutableHashableSet[E]) Union(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := s.Clone()
	out.AddAll(other.List()...)
	return out
}

// Intersection returns a new set containing only elements present in both sets.
func (s *MutableHashableSet[E]) Intersection(other ds.MutableSet[E]) ds.MutableSet[E] {
	mapping := hashmap.NewHashable[E, struct{}]()
	for k := range s.v.Iter() {
		if other.Contains(k) {
			mapping.Put(k, struct{}{})
		}
	}
	return &MutableHashableSet[E]{v: mapping}
}

// Difference returns a new set containing elements in this set but not in the other.
func (t *MutableHashableSet[E]) Difference(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := t.Clone()
	out.RemoveAll(other.List()...)
	return out
}

// SymmetricDifference returns a new set containing elements in either set but not both.
func (t *MutableHashableSet[E]) SymmetricDifference(other ds.MutableSet[E]) ds.MutableSet[E] {
	return t.Union(other).Difference(t.Intersection(other))
}

// SubSets returns all possible subsets of this set (power set).
func (t *MutableHashableSet[E]) SubSets() []ds.MutableSet[E] {
	result := make([]ds.MutableSet[E], 1<<t.Size())
	i := 0
	for subset := range t.IterSubSets() {
		result[i] = subset
		i++
	}
	return result
}

// Iter returns an iterator over all elements in the set.
func (s *MutableHashableSet[E]) Iter() iter.Seq[E] {
	return func(yield func(E) bool) {
		for el := range s.v.Iter() {
			if !yield(el) {
				return
			}
		}
	}
}

// Iter2 returns an iterator with index and element pairs.
func (s *MutableHashableSet[E]) Iter2() iter.Seq2[int, E] {
	return func(yield func(int, E) bool) {
		i := 0
		for el := range s.v.Iter() {
			if !yield(i, el) {
				return
			}
			i++
		}
	}
}

// IsSubSet returns true if all elements of this set are in the other set.
func (s *MutableHashableSet[E]) IsSubSet(of ds.MutableSet[E]) bool {
	for k := range s.Iter() {
		if !of.Contains(k) {
			return false
		}
	}
	return true
}

// IsProperSubSet returns true if this is a subset of other and they are not equal.
func (s *MutableHashableSet[E]) IsProperSubSet(of ds.MutableSet[E]) bool {
	return s.IsSubSet(of) && !s.Equal(of)
}

// IsSuperSet returns true if all elements of the other set are in this set.
func (s *MutableHashableSet[E]) IsSuperSet(of ds.MutableSet[E]) bool {
	for k := range of.Iter() {
		if _, exists := s.v.Get(k); !exists {
			return false
		}
	}
	return true
}

// IsProperSuperSet returns true if this is a superset of other and they are not equal.
func (s *MutableHashableSet[E]) IsProperSuperSet(of ds.MutableSet[E]) bool {
	return s.IsSuperSet(of) && !s.Equal(of)
}

// IterSubSets returns an iterator over all possible subsets of this set.
func (s *MutableHashableSet[E]) IterSubSets() iter.Seq[ds.MutableSet[E]] {
	return func(yield func(ds.MutableSet[E]) bool) {
		list := s.List()
		for i := 0; i <= s.Size(); i++ {
			for comb := range sliceutils.Combinations(list, uint(i)) {
				subset := NewHashable(comb...)
				if !yield(subset) {
					return
				}
			}
		}
	}
}

// List returns a slice of all elements in the set.
func (s *MutableHashableSet[E]) List() []E {
	return s.v.Keys()
}

// HashCode computes and returns the hash code for this set.
// The hash code is computed by XORing the hash codes of all elements.
func (s *MutableHashableSet[E]) HashCode() base.HashCode {
	if s.IsEmpty() {
		return base.HashCode(0)
	}
	l := s.List()
	if len(l) == 1 {
		return l[0].HashCode()
	}
	return sliceutils.Reduce(
		sliceutils.Map(l[1:], func(e E) ds.HashCode { return e.HashCode() }),
		l[0].HashCode(),
		func(a, b ds.HashCode) ds.HashCode { return a ^ b }, // must be commutative
	)
}
