# bimap

Bidirectional map implementations where both keys and values are unique.

## Overview

A BiMap maintains a one-to-one mapping between keys and values. Looking up by key or by value is equally efficient using the `Reverse()` method.

## Creating a BiMap

```go
import (
    "github.com/bronlabs/bron-crypto/pkg/base/datastructures/bimap"
    "github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

// Create with two empty maps (one for each direction)
m, err := bimap.NewMutableBiMap(
    hashmap.NewComparable[string, int](),
    hashmap.NewComparable[int, string](),
)
```

## Bidirectional Lookup

```go
// Forward lookup: key -> value
m.Put("one", 1)
value, exists := m.Get("one")  // 1, true

// Reverse lookup: value -> key
reversed := m.Reverse()
key, exists := reversed.Get(1)  // "one", true
```

## Thread-Safe BiMap

```go
inner, _ := bimap.NewMutableBiMap(
    hashmap.NewComparable[string, int](),
    hashmap.NewComparable[int, string](),
)
m := bimap.NewConcurrentBiMap(inner)

// Atomic operations
m.Compute("key", func(k string, old int, exists bool) (int, bool) {
    return old + 1, true
})

m.ComputeIfAbsent("key", func(k string) (int, bool) {
    return 42, true
})

m.ComputeIfPresent("key", func(k string, old int) (int, bool) {
    return old * 2, true
})
```

## Common Operations

```go
// Basic operations
m.Put("key", 123)
value, exists := m.Get("key")
m.Remove("key")
m.Clear()

// Query
m.Size()
m.IsEmpty()
m.ContainsKey("key")
m.Keys()
m.Values()

// Transform
filtered := m.Filter(func(k string) bool { return len(k) > 2 })
retained := m.Retain("a", "b", "c")

// Iterate
for k, v := range m.Iter() {
    // ...
}

// Freeze/Unfreeze
frozen := m.Freeze()
mutable := frozen.Unfreeze()
```

## Value Uniqueness

When putting a key-value pair, if the key already exists with a different value, the old value is removed from the reverse mapping:

```go
m.Put("a", 1)
m.Put("a", 2)  // "a" now maps to 2; reverse lookup for 1 no longer works
```
