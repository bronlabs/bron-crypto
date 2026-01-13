package datastructures

import (
	"iter"
)

// MapEntry represents a key-value pair in a map.
type MapEntry[K any, V any] struct {
	Key   K
	Value V
}

// AbstractMap defines the core operations for any map-like data structure.
// K is the key type, V is the value type, and C is the type used for size.
type AbstractMap[K, V, C any] interface {
	// Size returns the number of key-value pairs in the map.
	Size() C
	// Iter returns an iterator over all key-value pairs.
	Iter() iter.Seq2[K, V]
}

type immutableMap[K, V, AT, T any] interface {
	AbstractMap[K, V, int]
	Get(key K) (value V, exists bool)
	Retain(keys ...K) T
	Filter(predicate func(key K) bool) T
	ContainsKey(key K) bool
	IsEmpty() bool
	Keys() []K
	Values() []V

	Clonable[T]
}

type mutableMap[K, V, AT, T any] interface {
	immutableMap[K, V, AT, T]
	Put(key K, value V)
	TryPut(key K, newValue V) (replaced bool, oldValue V)
	Clear()
	Remove(key K)
	TryRemove(key K) (removed bool, removedValue V)
}

type mapThreadSafetyMixin[K, V, T any] interface {
	// Compute atomically computes a new value based on the key's current mapping.
	// The remappingFunction receives the key, current value (if any), and existence flag,
	// returning the new value and whether to store it (false removes the key).
	Compute(key K, remappingFunction func(key K, oldVal V, exist bool) (V, bool)) V
	// ComputeIfAbsent atomically computes a value only if the key is not present.
	// The mappingFunction returns the value to store and whether to store it.
	ComputeIfAbsent(key K, mappingFunction func(key K) (V, bool)) V
	// ComputeIfPresent atomically computes a new value only if the key is present.
	// The remappingFunction returns the new value and whether to keep it (false removes the key).
	ComputeIfPresent(key K, remappingFunction func(key K, oldVal V) (V, bool)) V
}

// MutableMap is a mutable map interface supporting put, remove, and clear operations.
// Use Freeze to obtain an immutable snapshot.
type MutableMap[K, V any] interface {
	mutableMap[K, V, MutableMap[K, V], MutableMap[K, V]]
	// Enumerate returns an iterator with index and MapEntry pairs.
	Enumerate() iter.Seq2[int, MapEntry[K, V]]
	// Freeze returns an immutable snapshot of this map.
	Freeze() Map[K, V]
}

// Map is an immutable map interface providing read-only access to key-value pairs.
// Use Unfreeze to obtain a mutable copy.
type Map[K, V any] interface {
	immutableMap[K, V, Map[K, V], Map[K, V]]
	// Enumerate returns an iterator with index and MapEntry pairs.
	Enumerate() iter.Seq2[int, MapEntry[K, V]]
	// Unfreeze returns a mutable copy of this map.
	Unfreeze() MutableMap[K, V]
}

// ConcurrentMap is a thread-safe map interface supporting atomic compute operations.
// All methods are safe for concurrent use by multiple goroutines.
type ConcurrentMap[K, V any] interface {
	mutableMap[K, V, Map[K, V], ConcurrentMap[K, V]]
	// Enumerate returns an iterator with index and MapEntry pairs.
	Enumerate() iter.Seq2[int, MapEntry[K, V]]
	mapThreadSafetyMixin[K, V, ConcurrentMap[K, V]]
}

// MutableBiMap is a mutable bidirectional map where both keys and values are unique.
// Looking up by key or by value is equally efficient via the Reverse method.
type MutableBiMap[K, V any] interface {
	mutableMap[K, V, BiMap[K, V], MutableBiMap[K, V]]
	// Reverse returns a view of this bimap with keys and values swapped.
	Reverse() MutableBiMap[V, K]
	// Freeze returns an immutable snapshot of this bimap.
	Freeze() BiMap[K, V]
}

// BiMap is an immutable bidirectional map where both keys and values are unique.
// Looking up by key or by value is equally efficient via the Reverse method.
type BiMap[K, V any] interface {
	immutableMap[K, V, BiMap[K, V], BiMap[K, V]]
	// Reverse returns a view of this bimap with keys and values swapped.
	Reverse() BiMap[V, K]
	// Unfreeze returns a mutable copy of this bimap.
	Unfreeze() MutableBiMap[K, V]
}

// ConcurrentBiMap is a thread-safe bidirectional map supporting atomic compute operations.
// All methods are safe for concurrent use by multiple goroutines.
type ConcurrentBiMap[K, V any] interface {
	mutableMap[K, V, BiMap[K, V], ConcurrentBiMap[K, V]]
	// Reverse returns a thread-safe view of this bimap with keys and values swapped.
	Reverse() ConcurrentBiMap[V, K]
	mapThreadSafetyMixin[K, V, ConcurrentBiMap[K, V]]
}
