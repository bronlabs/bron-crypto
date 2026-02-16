package bitset

import (
	"iter"
	"math/bits"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"golang.org/x/exp/constraints"
)

// NewImmutableBitSet creates a new immutable BitSet containing the given elements.
// Elements must be in the range [1, 64]. Elements outside this range will panic.
func NewImmutableBitSet[U constraints.Unsigned](elements ...U) ImmutableBitSet[U] {
	var s BitSet[U]
	s.AddAll(elements...)
	return ImmutableBitSet[U](s)
}

// ImmutableBitSet is an immutable set of uint64 values in the range [1, 64].
// Unlike BitSet, all methods use value receivers to ensure true immutability
// through Go's value semantics. Set operations return new ImmutableBitSet values
// without modifying the original.
//
// Memory: 8 bytes (1 uint64)
// Operations: O(1) for all operations except iteration and subset generation
//
// Implements ds.Set[U].
type ImmutableBitSet[U constraints.Unsigned] uint64

// Unfreeze returns a mutable copy of the immutable set.
func (s ImmutableBitSet[U]) Unfreeze() ds.MutableSet[U] {
	b := BitSet[U](s)
	return &b
}

// Contains returns true if the element is in the set.
// Returns false for elements outside the valid range [1, 64].
func (s ImmutableBitSet[U]) Contains(e U) bool {
	b := BitSet[U](s)
	return b.Contains(e)
}

// Iter returns an iterator over all elements in increasing order (1..64).
func (s ImmutableBitSet[U]) Iter() iter.Seq[U] {
	b := BitSet[U](s)
	return b.Iter()
}

// Iter2 returns an iterator with index and element pairs.
// Elements are yielded in increasing order with their iteration index.
func (s ImmutableBitSet[U]) Iter2() iter.Seq2[int, U] {
	b := BitSet[U](s)
	return b.Iter2()
}

// Size returns the number of elements in the set (same as Cardinality).
func (s ImmutableBitSet[U]) Size() int {
	return bits.OnesCount64(uint64(s))
}

// Cardinality returns the number of elements in the set.
// This is computed using the population count (number of 1 bits).
func (s ImmutableBitSet[U]) Cardinality() int {
	return bits.OnesCount64(uint64(s))
}

// IsEmpty returns true if the set contains no elements.
func (s ImmutableBitSet[U]) IsEmpty() bool {
	return s == 0
}

// Union returns a new immutable set containing all elements from both sets.
// Panics if other is not an ImmutableBitSet.
func (s ImmutableBitSet[U]) Union(other ds.Set[U]) ds.Set[U] {
	o, ok := other.(ImmutableBitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return s | o
}

// Intersection returns a new immutable set containing only elements present in both sets.
// Panics if other is not an ImmutableBitSet.
func (s ImmutableBitSet[U]) Intersection(other ds.Set[U]) ds.Set[U] {
	o, ok := other.(ImmutableBitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return s & o
}

// Difference returns a new immutable set containing elements in this set but not in the other.
// Panics if other is not an ImmutableBitSet.
func (s ImmutableBitSet[U]) Difference(other ds.Set[U]) ds.Set[U] {
	o, ok := other.(ImmutableBitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return s &^ o
}

// SymmetricDifference returns a new immutable set containing elements in either set but not both.
// Panics if other is not an ImmutableBitSet.
func (s ImmutableBitSet[U]) SymmetricDifference(other ds.Set[U]) ds.Set[U] {
	o, ok := other.(ImmutableBitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return s ^ o
}

// SubSets returns all possible subsets of this set (the power set).
// For a set of size n, returns 2^n subsets.
func (s ImmutableBitSet[U]) SubSets() []ds.Set[U] {
	return slices.Collect(s.IterSubSets())
}

// IsSubSet returns true if all elements of this set are in the other set.
// Delegates to the mutable BitSet implementation for the actual check.
func (s ImmutableBitSet[U]) IsSubSet(of ds.Set[U]) bool {
	x := BitSet[U](s)
	return (&x).IsSubSet(of.Unfreeze())
}

// IsProperSubSet returns true if this is a proper (strict) subset of the other set.
// A proper subset is a subset that is not equal to the other set.
func (s ImmutableBitSet[U]) IsProperSubSet(of ds.Set[U]) bool {
	return s.IsSubSet(of) && !s.Equal(of)
}

// IsSuperSet returns true if all elements of the other set are in this set.
func (s ImmutableBitSet[U]) IsSuperSet(of ds.Set[U]) bool {
	return of.IsSubSet(s)
}

// IsProperSuperSet returns true if this is a proper (strict) superset of the other set.
// A proper superset is a superset that is not equal to the other set.
func (s ImmutableBitSet[U]) IsProperSuperSet(of ds.Set[U]) bool {
	return of.IsProperSubSet(s)
}

// IterSubSets returns an iterator over all subsets of this set.
// Uses the standard submask iteration algorithm, visiting all 2^n subsets.
func (s ImmutableBitSet[U]) IterSubSets() iter.Seq[ds.Set[U]] {
	return func(yield func(ds.Set[U]) bool) {
		sub := uint64(s)
		for {
			if !yield(ImmutableBitSet[U](sub)) {
				return
			}
			if sub == 0 {
				return
			}
			sub = (sub - 1) & uint64(s)
		}
	}
}

// List returns all elements as a slice in increasing order.
func (s ImmutableBitSet[U]) List() []U {
	return slices.Collect(s.Iter())
}

// Equal returns true if both sets contain exactly the same elements.
// Returns false if other is not an ImmutableBitSet.
func (s ImmutableBitSet[U]) Equal(other ds.Set[U]) bool {
	o, ok := other.(ImmutableBitSet[U])
	return ok && s == o
}

// Clone returns an immutable copy of this set.
// Since ImmutableBitSet uses value semantics, this simply returns the value itself.
func (s ImmutableBitSet[U]) Clone() ds.Set[U] {
	return s
}
