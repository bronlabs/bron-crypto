package datastructures

import (
	"encoding/json"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base"
)

type AbstractSet[E, C any] interface {
	Cardinality() C
	Iter() iter.Seq[E]
}

type immutableSet[E, T any] interface {
	AbstractSet[E, int]
	Contains(e E) bool
	Iter2() iter.Seq2[int, E]

	Size() int
	IsEmpty() bool

	Union(other T) T
	Intersection(other T) T
	Difference(other T) T
	SymmetricDifference(other T) T
	SubSets() []T
	IsSubSet(of T) bool
	IsProperSubSet(of T) bool
	IsSuperSet(of T) bool
	IsProperSuperSet(of T) bool
	IterSubSets() iter.Seq[T]
	List() []E

	base.Equatable[T]
	base.Clonable[T]
	json.Marshaler
}

type mutableSet[E, T any] interface {
	immutableSet[E, T]
	Add(e E)
	AddAll(es ...E)
	Remove(e E)
	RemoveAll(es ...E)
	Clear()
}

type Set[E any] interface {
	immutableSet[E, Set[E]]
	Unfreeze() MutableSet[E]
}

type MutableSet[E any] interface {
	mutableSet[E, MutableSet[E]]
	Freeze() Set[E]
	// ThreadSafe() ConcurrentSet[E]
}

type setThreadSafetyMixin[E any] interface {
	Compute(e E, remappingFunction func(e E, exist bool) (E, bool)) E
	ComputeIfAbsent(e E, mappingFunction func(e E) (E, bool)) E
	ComputeIfPresent(e E, remappingFunction func(e E) (E, bool)) E
}

type ConcurrentSet[E any] interface {
	mutableSet[E, ConcurrentSet[E]]
	setThreadSafetyMixin[E]
}
