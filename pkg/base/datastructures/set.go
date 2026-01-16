package datastructures

import (
	"iter"
)

// AbstractSet defines the core operations for any set-like data structure.
// E is the element type and C is the type used for cardinality.
type AbstractSet[E, C any] interface {
	// Cardinality returns the number of elements in the set.
	Cardinality() C
	// Iter returns an iterator over all elements in the set.
	Iter() iter.Seq[E]
	// Contains returns true if the element is in the set.
	Contains(e E) bool
}

type immutableSet[E, AT, T any] interface {
	AbstractSet[E, int]
	Iter2() iter.Seq2[int, E]

	Size() int
	IsEmpty() bool

	Union(other AT) T
	Intersection(other AT) T
	Difference(other AT) T
	SymmetricDifference(other AT) T
	SubSets() []AT
	IsSubSet(of AT) bool
	IsProperSubSet(of AT) bool
	IsSuperSet(of AT) bool
	IsProperSuperSet(of AT) bool
	IterSubSets() iter.Seq[AT]
	List() []E

	Clonable[T]
	Equatable[AT]
}

type mutableSet[E, AT, T any] interface {
	immutableSet[E, AT, T]
	Add(e E)
	AddAll(es ...E)
	Remove(e E)
	RemoveAll(es ...E)
	Clear()
}

// Set is an immutable set interface providing read-only access to set elements.
// Use Unfreeze to obtain a mutable copy.
type Set[E any] interface {
	immutableSet[E, Set[E], Set[E]]
	// Unfreeze returns a mutable copy of this set.
	Unfreeze() MutableSet[E]
}

// MutableSet is a mutable set interface supporting add, remove, and clear operations.
// Use Freeze to obtain an immutable snapshot.
type MutableSet[E any] interface {
	mutableSet[E, MutableSet[E], MutableSet[E]]
	// Freeze returns an immutable snapshot of this set.
	Freeze() Set[E]
}

type setThreadSafetyMixin[E any] interface {
	// Compute atomically computes a new value based on the element's presence.
	// The remappingFunction receives the element and whether it exists, returning
	// the new value and whether to store it.
	Compute(e E, remappingFunction func(e E, exist bool) (E, bool)) E
	// ComputeIfAbsent atomically computes a value only if the element is absent.
	// The mappingFunction returns the value to store and whether to store it.
	ComputeIfAbsent(e E, mappingFunction func(e E) (E, bool)) E
	// ComputeIfPresent atomically computes a value only if the element is present.
	// The remappingFunction returns the new value and whether to keep it.
	ComputeIfPresent(e E, remappingFunction func(e E) (E, bool)) E
}

// ConcurrentSet is a thread-safe set interface supporting atomic compute operations.
// All methods are safe for concurrent use by multiple goroutines.
type ConcurrentSet[E any] interface {
	mutableSet[E, Set[E], ConcurrentSet[E]]
	setThreadSafetyMixin[E]
}
