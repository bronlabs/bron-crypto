# datastructures

Generic data structure interfaces and implementations for Go.

## Overview

This package defines interfaces for common data structures with support for:
- **Immutability**: `Freeze()` creates immutable snapshots, `Unfreeze()` creates mutable copies
- **Concurrency**: Thread-safe implementations with atomic compute operations
- **Generics**: Type-safe collections using Go generics

## Interfaces

### Maps
- `Map[K, V]` - Immutable key-value map
- `MutableMap[K, V]` - Mutable key-value map
- `ConcurrentMap[K, V]` - Thread-safe map with atomic operations

### BiMaps (Bidirectional Maps)
- `BiMap[K, V]` - Immutable bidirectional map (unique keys and values)
- `MutableBiMap[K, V]` - Mutable bidirectional map
- `ConcurrentBiMap[K, V]` - Thread-safe bidirectional map

### Sets
- `Set[E]` - Immutable set
- `MutableSet[E]` - Mutable set with union, intersection, difference operations
- `ConcurrentSet[E]` - Thread-safe set with atomic operations

### Tables
- `Table[E]` - Mutable 2D table with row/column operations
- `ImmutableTable[E]` - Immutable 2D table

## Subpackages

- `hashmap` - Hash-based map implementations
- `hashset` - Hash-based set implementations
- `bimap` - Bidirectional map implementations

## Key Types

```go
// HashCode for custom hashable types
type HashCode uint64

// Hashable interface for types with custom equality and hashing
type Hashable[T any] interface {
    Equal(rhs T) bool
    HashCode() HashCode
}
```

## Usage

```go
import (
    "github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
    "github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

// Create a mutable map
m := hashmap.NewComparable[string, int]()
m.Put("key", 42)

// Create an immutable snapshot
frozen := m.Freeze()

// Create a thread-safe map
concurrent := hashmap.NewConcurrentMap(m)
```
