package datastructures

import "encoding/json"

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
