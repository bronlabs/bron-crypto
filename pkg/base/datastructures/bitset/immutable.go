package bitset

import (
	"iter"
	"math/bits"
	"slices"

	"golang.org/x/exp/constraints"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
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
func (ib ImmutableBitSet[U]) Unfreeze() ds.MutableSet[U] {
	b := BitSet[U](ib)
	return &b
}

// Contains returns true if the element is in the set.
// Returns false for elements outside the valid range [1, 64].
func (ib ImmutableBitSet[U]) Contains(e U) bool {
	b := BitSet[U](ib)
	return b.Contains(e)
}

// Iter returns an iterator over all elements in increasing order (1..64).
func (ib ImmutableBitSet[U]) Iter() iter.Seq[U] {
	b := BitSet[U](ib)
	return b.Iter()
}

// Iter2 returns an iterator with index and element pairs.
// Elements are yielded in increasing order with their iteration index.
func (ib ImmutableBitSet[U]) Iter2() iter.Seq2[int, U] {
	b := BitSet[U](ib)
	return b.Iter2()
}

// Size returns the number of elements in the set (same as Cardinality).
func (ib ImmutableBitSet[U]) Size() int {
	return bits.OnesCount64(uint64(ib))
}

// Cardinality returns the number of elements in the set.
// This is computed using the population count (number of 1 bits).
func (ib ImmutableBitSet[U]) Cardinality() int {
	return bits.OnesCount64(uint64(ib))
}

// IsEmpty returns true if the set contains no elements.
func (ib ImmutableBitSet[U]) IsEmpty() bool {
	return ib == 0
}

// Union returns a new immutable set containing all elements from both sets.
// Panics if other is not an ImmutableBitSet.
func (ib ImmutableBitSet[U]) Union(other ds.Set[U]) ds.Set[U] {
	o, ok := other.(ImmutableBitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return ib | o
}

// Intersection returns a new immutable set containing only elements present in both sets.
// Panics if other is not an ImmutableBitSet.
func (ib ImmutableBitSet[U]) Intersection(other ds.Set[U]) ds.Set[U] {
	o, ok := other.(ImmutableBitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return ib & o
}

// Difference returns a new immutable set containing elements in this set but not in the other.
// Panics if other is not an ImmutableBitSet.
func (ib ImmutableBitSet[U]) Difference(other ds.Set[U]) ds.Set[U] {
	o, ok := other.(ImmutableBitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return ib &^ o
}

// SymmetricDifference returns a new immutable set containing elements in either set but not both.
// Panics if other is not an ImmutableBitSet.
func (ib ImmutableBitSet[U]) SymmetricDifference(other ds.Set[U]) ds.Set[U] {
	o, ok := other.(ImmutableBitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return ib ^ o
}

// SubSets returns all possible subsets of this set (the power set).
// For a set of size n, returns 2^n subsets.
func (ib ImmutableBitSet[U]) SubSets() []ds.Set[U] {
	return slices.Collect(ib.IterSubSets())
}

// IsSubSet returns true if all elements of this set are in the other set.
// Delegates to the mutable BitSet implementation for the actual check.
func (ib ImmutableBitSet[U]) IsSubSet(of ds.Set[U]) bool {
	x := BitSet[U](ib)
	return (&x).IsSubSet(of.Unfreeze())
}

// IsProperSubSet returns true if this is a proper (strict) subset of the other set.
// A proper subset is a subset that is not equal to the other set.
func (ib ImmutableBitSet[U]) IsProperSubSet(of ds.Set[U]) bool {
	return ib.IsSubSet(of) && !ib.Equal(of)
}

// IsSuperSet returns true if all elements of the other set are in this set.
func (ib ImmutableBitSet[U]) IsSuperSet(of ds.Set[U]) bool {
	return of.IsSubSet(ib)
}

// IsProperSuperSet returns true if this is a proper (strict) superset of the other set.
// A proper superset is a superset that is not equal to the other set.
func (ib ImmutableBitSet[U]) IsProperSuperSet(of ds.Set[U]) bool {
	return of.IsProperSubSet(ib)
}

// IterSubSets returns an iterator over all subsets of this set.
// Uses the standard submask iteration algorithm, visiting all 2^n subsets.
func (ib ImmutableBitSet[U]) IterSubSets() iter.Seq[ds.Set[U]] {
	return func(yield func(ds.Set[U]) bool) {
		sub := uint64(ib)
		for {
			if !yield(ImmutableBitSet[U](sub)) {
				return
			}
			if sub == 0 {
				return
			}
			sub = (sub - 1) & uint64(ib)
		}
	}
}

// List returns all elements as a slice in increasing order.
func (ib ImmutableBitSet[U]) List() []U {
	return slices.Collect(ib.Iter())
}

// Equal returns true if both sets contain exactly the same elements.
// Returns false if other is not an ImmutableBitSet.
func (ib ImmutableBitSet[U]) Equal(other ds.Set[U]) bool {
	o, ok := other.(ImmutableBitSet[U])
	return ok && ib == o
}

// Clone returns an immutable copy of this set.
// Since ImmutableBitSet uses value semantics, this simply returns the value itself.
func (ib ImmutableBitSet[U]) Clone() ds.Set[U] {
	return ib
}
