package bitset

import (
	"iter"
	"math/bits"
	"slices"

	"golang.org/x/exp/constraints"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

// NewBitSet creates a new mutable BitSet containing the given elements.
// Elements must be in the range [1, 64]. Elements outside this range will panic.
func NewBitSet[U constraints.Unsigned](elements ...U) *BitSet[U] {
	var s BitSet[U]
	s.AddAll(elements...)
	return &s
}

// BitSet is a mutable set of uint64 values in the range [1, 64], represented
// as a single uint64 bitmask. Each bit position i (0-63) represents whether
// element i+1 is in the set. This provides extremely fast set operations
// using bitwise operations.
//
// Memory: 8 bytes (1 uint64)
// Operations: O(1) for all operations except iteration and subset generation
//
// Implements ds.MutableSet[U].
type BitSet[U constraints.Unsigned] uint64

// mask returns the bitmask for element e. Elements are 1-indexed (1-64),
// corresponding to bits 0-63 in the uint64.
// Returns (mask, true) if e is in range [1, 64], or (0, false) otherwise.
func mask(e uint64) (uint64, bool) {
	if e < 1 || e > 64 {
		return 0, false
	}
	return 1 << (e - 1), true
}

// Cardinality returns the number of elements in the set.
// This is computed using the population count (number of 1 bits).
func (b *BitSet[U]) Cardinality() int {
	return bits.OnesCount64(uint64(*b))
}

// Iter returns an iterator over elements in increasing order (1..64).
func (b *BitSet[U]) Iter() iter.Seq[U] {
	return func(yield func(U) bool) {
		x := uint64(*b)
		for x != 0 {
			i := uint64(bits.TrailingZeros64(x))
			e := i + 1
			if !yield(U(e)) {
				return
			}
			x &= x - 1
		}
	}
}

// Contains returns true if the element is in the set.
// Returns false for elements outside the valid range [1, 64].
func (b *BitSet[U]) Contains(e U) bool {
	m, ok := mask(uint64(e))
	return ok && (uint64(*b)&m) != 0
}

// Iter2 returns an iterator with index and element pairs.
// Elements are yielded in increasing order with their iteration index.
func (b *BitSet[U]) Iter2() iter.Seq2[int, U] {
	return func(yield func(int, U) bool) {
		x := uint64(*b)
		idx := 0
		for x != 0 {
			i := uint64(bits.TrailingZeros64(x))
			e := i + 1
			if !yield(idx, U(e)) {
				return
			}
			x &= x - 1
			idx++
		}
	}
}

// Size returns the number of elements in the set (same as Cardinality).
func (b *BitSet[U]) Size() int {
	return b.Cardinality()
}

// IsEmpty returns true if the set contains no elements.
func (b *BitSet[U]) IsEmpty() bool {
	return *b == 0
}

// Union returns a new BitSet containing all elements from both sets.
// Panics if other is not a *BitSet.
func (b *BitSet[U]) Union(other ds.MutableSet[U]) ds.MutableSet[U] {
	o, ok := other.(*BitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	result := *b | *o
	return &result
}

// Intersection returns a new BitSet containing only elements present in both sets.
// Panics if other is not a *BitSet.
func (b *BitSet[U]) Intersection(other ds.MutableSet[U]) ds.MutableSet[U] {
	o, ok := other.(*BitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	result := *b & *o
	return &result
}

// Difference returns a new BitSet containing elements in this set but not in the other.
// Panics if other is not a *BitSet.
func (b *BitSet[U]) Difference(other ds.MutableSet[U]) ds.MutableSet[U] {
	o, ok := other.(*BitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	result := *b &^ *o
	return &result
}

// SymmetricDifference returns a new BitSet containing elements in either set but not both.
// Panics if other is not a *BitSet.
func (b *BitSet[U]) SymmetricDifference(other ds.MutableSet[U]) ds.MutableSet[U] {
	o, ok := other.(*BitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	result := *b ^ *o
	return &result
}

// SubSets returns all possible subsets of this set (the power set).
// For a set of size n, returns 2^n subsets.
func (b *BitSet[U]) SubSets() []ds.MutableSet[U] {
	return slices.Collect(b.IterSubSets())
}

// IsSubSet returns true if all elements of this set are in the other set.
// Uses efficient bitwise check: s ⊆ other iff (s &^ other) == 0.
// Panics if other is not a *BitSet.
func (b *BitSet[U]) IsSubSet(of ds.MutableSet[U]) bool {
	o, ok := of.(*BitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return (*b &^ *o) == 0
}

// IsProperSubSet returns true if this is a proper (strict) subset of the other set.
// A proper subset is a subset that is not equal to the other set.
// Panics if other is not a *BitSet.
func (b *BitSet[U]) IsProperSubSet(of ds.MutableSet[U]) bool {
	o, ok := of.(*BitSet[U])
	if !ok {
		panic("other set is not a BitSet")
	}
	return (*b != *o) && ((*b &^ *o) == 0)
}

// IsSuperSet returns true if all elements of the other set are in this set.
func (b *BitSet[U]) IsSuperSet(of ds.MutableSet[U]) bool {
	return of.IsSubSet(b)
}

// IsProperSuperSet returns true if this is a proper (strict) superset of the other set.
// A proper superset is a superset that is not equal to the other set.
func (b *BitSet[U]) IsProperSuperSet(of ds.MutableSet[U]) bool {
	return of.IsProperSubSet(b)
}

// IterSubSets returns an iterator over all subsets of this set.
// Uses the standard submask iteration algorithm: iterates from the full set
// down to the empty set, visiting all 2^n subsets.
func (b *BitSet[U]) IterSubSets() iter.Seq[ds.MutableSet[U]] {
	return func(yield func(ds.MutableSet[U]) bool) {
		sub := *b
		for {
			c := sub
			if !yield(&c) {
				return
			}
			if sub == 0 {
				return
			}
			sub = (sub - 1) & *b
		}
	}
}

// List returns all elements as a slice in increasing order.
func (b *BitSet[U]) List() []U {
	return slices.Collect(b.Iter())
}

// Clone returns a mutable copy of this set.
func (b *BitSet[U]) Clone() ds.MutableSet[U] {
	clone := *b
	return &clone
}

// Equal returns true if both sets contain exactly the same elements.
// Returns false if other is not a *BitSet.
func (b *BitSet[U]) Equal(other ds.MutableSet[U]) bool {
	o, ok := other.(*BitSet[U])
	if !ok {
		return false
	}
	return *b == *o
}

// Add adds an element to the set.
// Panics if e is not in the range [1, 64].
func (b *BitSet[U]) Add(e U) {
	m, ok := mask(uint64(e))
	if !ok {
		panic("element out of range")
	}
	*b |= BitSet[U](m)
}

// AddAll adds multiple elements to the set.
// Panics if any element is not in the range [1, 64].
func (b *BitSet[U]) AddAll(es ...U) {
	for _, e := range es {
		b.Add(e)
	}
}

// Remove removes an element from the set.
// Panics if e is not in the range [1, 64].
func (b *BitSet[U]) Remove(e U) {
	m, ok := mask(uint64(e))
	if !ok {
		panic("element out of range")
	}
	*b &^= BitSet[U](m)
}

// RemoveAll removes multiple elements from the set.
// Panics if any element is not in the range [1, 64].
func (b *BitSet[U]) RemoveAll(es ...U) {
	for _, e := range es {
		b.Remove(e)
	}
}

// Clear removes all elements from the set, resetting it to empty.
func (b *BitSet[U]) Clear() {
	*b = 0
}

// Freeze returns an immutable copy of this set.
// The immutable copy uses value semantics for guaranteed immutability.
func (b *BitSet[U]) Freeze() ds.Set[U] {
	return ImmutableBitSet[U](*b)
}
