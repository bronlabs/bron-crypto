package datastructures

import (
	"encoding/json"

	"github.com/cronokirby/saferith"
)

type Incomparable [0]func()

type Equatable[K any] interface {
	Equal(rhs K) bool
}

type Hashable[K any] interface {
	Equatable[K]
	HashCode() uint64
}

type MapEntry[K any, V any] struct {
	Key   K
	Value V
}

type Map[K any, V any] interface {
	Get(key K) (value V, exists bool)
	Retain(keys Set[K]) Map[K, V]
	Filter(predicate func(key K) bool) Map[K, V]
	ContainsKey(key K) bool
	Put(key K, value V)
	TryPut(key K, newValue V) (replaced bool, oldValue V)
	Clear()
	Size() int
	IsEmpty() bool
	Remove(key K)
	TryRemove(key K) (removed bool, removedValue V)
	Keys() []K
	Values() []V
	Iter() <-chan MapEntry[K, V]
	Clone() Map[K, V]
	json.Marshaler
}

type BiMap[K any, V any] interface {
	Map[K, V]
	Reverse() BiMap[V, K]
}

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
