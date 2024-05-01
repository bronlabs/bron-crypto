package datastructures

import (
	"encoding/json"

	"github.com/cronokirby/saferith"
)

type AbstractSet[E any] interface {
	Cardinality() *saferith.Nat
	Contains(e E) bool
	Iter() <-chan E
}

type Set[E any] interface {
	AbstractSet[E]
	Add(e E)
	AddAll(es ...E)
	Remove(e E)
	Clear()
	Size() int
	IsEmpty() bool
	Union(other Set[E]) Set[E]
	Intersection(other Set[E]) Set[E]
	Difference(other Set[E]) Set[E]
	SymmetricDifference(other Set[E]) Set[E]
	SubSets() []Set[E]
	IsSubSet(other Set[E]) bool
	IsProperSubSet(other Set[E]) bool
	IsSuperSet(other Set[E]) bool
	IsProperSuperSet(other Set[E]) bool
	IterSubSets() <-chan Set[E]
	List() []E
	Clone() Set[E]

	Equatable[Set[E]]
	json.Marshaler
}
