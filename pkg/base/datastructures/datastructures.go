package datastructures

import (
	"encoding/json"
	"iter"

	"github.com/cronokirby/saferith"
)

type Incomparable [0]func()

type Equatable[K any] interface {
	Equal(rhs K) bool
}
type Clonable[T any] interface {
	Clone() T
}

type Hashable[K any] interface {
	Equatable[K]
	HashCode() uint64
}

type MapEntry[K any, V any] struct {
	Key   K
	Value V
}

type immutableMap[K, V, T any] interface {
	Get(key K) (value V, exists bool)
	Retain(keys Set[K]) T
	Filter(predicate func(key K) bool) T
	ContainsKey(key K) bool
	Size() int
	IsEmpty() bool
	Keys() []K
	Values() []V

	Iter() iter.Seq2[K, V]
	Clone() T
	json.Marshaler
}

type ImmutableMap[K any, V any] interface {
	immutableMap[K, V, ImmutableMap[K, V]]
}

type Map[K any, V any] interface {
	immutableMap[K, V, Map[K, V]]
	Put(key K, value V)
	TryPut(key K, newValue V) (replaced bool, oldValue V)
	Clear()
	Remove(key K)
	TryRemove(key K) (removed bool, removedValue V)

	// Freeze() ImmutableMap[K, V]
}

type BiMap[K any, V any] interface {
	Map[K, V]
	Reverse() BiMap[V, K]
}

type ImmutableBiMap[K any, V any] interface {
	ImmutableMap[K, V]
	Reverse() ImmutableBiMap[V, K]
}

type ConcurrentBiMap[K any, V any] interface {
	BiMap[K, V]
	ConcurrentMap[K, V]
}

type ConcurrentMap[K any, V any] interface {
	Map[K, V]

	Compute(key K, remappingFunction func(key K, oldVal V, exist bool) (V, bool)) V
	ComputeIfAbsent(key K, mappingFunction func(key K) (V, bool)) V
	ComputeIfPresent(key K, remappingFunction func(key K, oldVal V) (V, bool)) V
}

type ConcurrentSet[E any] interface {
	Set[E]

	Compute(e E, remappingFunction func(e E, exist bool) (E, bool)) E
	ComputeIfAbsent(e E, mappingFunction func(e E) (E, bool)) E
	ComputeIfPresent(e E, remappingFunction func(e E) (E, bool)) E
}

type AbstractSet[E, C any] interface {
	Cardinality() C
	Contains(e E) bool
	Iter() iter.Seq[E]
}

type Set[E any] interface {
	AbstractSet[E, *saferith.Nat]
	immutableSet[E, Set[E]]
	Add(e E)
	AddAll(es ...E)
	Remove(e E)
	Clear()

	// Freeze() ImmutableSet[E]
}

type immutableSet[E, T any] interface {
	AbstractSet[E, *saferith.Nat]
	Size() int
	IsEmpty() bool
	Union(other T) T
	Intersection(other T) T
	Difference(other T) T
	SymmetricDifference(other T) T
	SubSets() []T
	IsSubSet(other T) bool
	IsProperSubSet(other T) bool
	IsSuperSet(other T) bool
	IsProperSuperSet(other T) bool
	// IterSubSets() iter.Seq[T]
	IterSubSets() <-chan Set[E]
	List() []E
	Clone() T

	Equatable[T]
	json.Marshaler
}

type ImmutableSet[E any] interface {
	immutableSet[E, ImmutableSet[E]]
}
