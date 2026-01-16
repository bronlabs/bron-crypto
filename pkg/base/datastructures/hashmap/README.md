# hashmap

Hash-based map implementations.

## Types

### For Comparable Keys

Use these when your key type supports `==` comparison (strings, integers, etc.):

```go
// Mutable map
m := hashmap.NewComparable[string, int]()
m.Put("a", 1)
m.Put("b", 2)

// From entries
m := hashmap.NewComparable(
    ds.MapEntry[string, int]{Key: "a", Value: 1},
    ds.MapEntry[string, int]{Key: "b", Value: 2},
)

// From parallel slices
m, err := hashmap.CollectToComparable([]string{"a", "b"}, []int{1, 2})

// Immutable map
frozen := hashmap.NewImmutableComparable[string, int]()
```

### For Hashable Keys

Use these when your key type implements `ds.Hashable[T]`:

```go
// Mutable map
m := hashmap.NewHashable[*MyKey, int]()

// From parallel slices
m, err := hashmap.CollectToHashable(keys, values)

// Immutable map
frozen := hashmap.NewImmutableHashable[*MyKey, int]()
```

### Thread-Safe Maps

Wrap any mutable map for concurrent access:

```go
inner := hashmap.NewComparable[string, int]()
m := hashmap.NewConcurrentMap(inner)

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
value, exists := m.Get("key")
m.Put("key", value)
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
