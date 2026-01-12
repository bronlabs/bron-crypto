package datastructures

import (
	"encoding/json"
	"iter"
)

type MapEntry[K any, V any] struct {
	Key   K
	Value V
}

type AbstractMap[K, V, C any] interface {
	Size() C
	Iter() iter.Seq2[K, V]
}

type immutableMap[K, V, T any] interface {
	AbstractMap[K, V, int]
	Get(key K) (value V, exists bool)
	Retain(keys ...K) T
	Filter(predicate func(key K) bool) T
	ContainsKey(key K) bool
	IsSubMap(other T, eq func(a, b V) bool) bool
	IsProperSubMap(other T, eq func(a, b V) bool) bool
	IsSuperMap(other T, eq func(a, b V) bool) bool
	IsProperSuperMap(other T, eq func(a, b V) bool) bool
	IsEmpty() bool
	Keys() []K
	Values() []V
	Enumerate() iter.Seq2[int, MapEntry[K, V]]
	Clonable[T]
	json.Marshaler
}

type mutableMap[K, V, T any] interface {
	immutableMap[K, V, T]
	Put(key K, value V)
	TryPut(key K, newValue V) (replaced bool, oldValue V)
	Clear()
	Remove(key K)
	TryRemove(key K) (removed bool, removedValue V)
}

type mapThreadSafetyMixin[K, V, T any] interface {
	Compute(key K, remappingFunction func(key K, oldVal V, exist bool) (V, bool)) V
	ComputeIfAbsent(key K, mappingFunction func(key K) (V, bool)) V
	ComputeIfPresent(key K, remappingFunction func(key K, oldVal V) (V, bool)) V
}

type MutableMap[K, V any] interface {
	mutableMap[K, V, MutableMap[K, V]]
	Freeze() Map[K, V]
}

type Map[K, V any] interface {
	immutableMap[K, V, Map[K, V]]
	Unfreeze() MutableMap[K, V]
}

type ConcurrentMap[K, V any] interface {
	mutableMap[K, V, ConcurrentMap[K, V]]
	mapThreadSafetyMixin[K, V, ConcurrentMap[K, V]]
}

type MutableBiMap[K, V any] interface {
	mutableMap[K, V, MutableBiMap[K, V]]
	Reverse() MutableBiMap[V, K]
}

type BiMap[K, V any] interface {
	immutableMap[K, V, BiMap[K, V]]
	Reverse() BiMap[V, K]
}

type ConcurrentBiMap[K, V any] interface {
	mutableMap[K, V, ConcurrentBiMap[K, V]]
	Reverse() ConcurrentBiMap[V, K]
	mapThreadSafetyMixin[K, V, ConcurrentBiMap[K, V]]
}
