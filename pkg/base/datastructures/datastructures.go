package datastructures

import (
	"encoding/json"
)

type Incomparable [0]func()

type Hashable[K any] interface {
	HashCode() uint64
	Equal(rhs K) bool
}

type KeyValuePair[K any, V any] struct {
	Key   K
	Value V
}

type LeftRight[L any, R any] struct {
	Left  L
	Right R
}

type HashMap[K any, V any] interface {
	Get(key K) (value V, exists bool)
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
	Iter() <-chan KeyValuePair[K, V]
	Clone() HashMap[K, V]
	json.Marshaler
}

type BiMap[L any, R any] interface {
	LookUpLeft(l L) (r R, exists bool)
	LookUpRight(r R) (l L, exists bool)
	LookUp(l L, r R) bool
	Put(l L, r R)
	TryPut(l L, r R) (replaced bool, oldLeft L, oldRight R)
	Clear()
	Size() int
	IsEmpty() bool
	Remove(l L, r R)
	TryRemove(l L, r R) (removed bool)
	RemoveLeft(l L)
	TryRemoveLeft(l L) (removed bool, r R)
	RemoveRight(r R)
	TryRemoveRight(r R) (removed bool, l L)
	Left() []L
	Right() []R
	Iter() <-chan LeftRight[L, R]
	Clone() BiMap[L, R]
	CloneLeft() HashMap[L, R]
	CloneRight() HashMap[R, L]
	json.Marshaler
}

type HashSet[E any] interface {
	Contains(e E) bool
	Add(e E)
	Merge(es ...E)
	Remove(e E)
	Clear()
	Equal(other HashSet[E]) bool
	Size() int
	IsEmpty() bool
	Union(other HashSet[E]) HashSet[E]
	Intersection(other HashSet[E]) HashSet[E]
	Difference(other HashSet[E]) HashSet[E]
	SymmetricDifference(other HashSet[E]) HashSet[E]
	SubSets() []HashSet[E]
	IsSubSet(other HashSet[E]) bool
	IsProperSubSet(other HashSet[E]) bool
	IsSuperSet(other HashSet[E]) bool
	IsProperSuperSet(other HashSet[E]) bool
	Iter() <-chan E
	IterSubSets() <-chan HashSet[E]
	List() []E
	Clone() HashSet[E]
	Hashable[HashSet[E]]
	json.Marshaler
}
