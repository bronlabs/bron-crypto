# hashset

Hash-based set implementations.

## Types

### For Comparable Elements

Use when elements support `==` comparison:

```go
// Create with initial elements
s := hashset.NewComparable("a", "b", "c")

// Empty set
s := hashset.NewComparable[string]()
```

### For Hashable Elements

Use when elements implement `ds.Hashable[T]`:

```go
s := hashset.NewHashable(elem1, elem2, elem3)
```

### Thread-Safe Sets

Wrap any mutable set for concurrent access:

```go
inner := hashset.NewComparable[string]()
s := hashset.NewConcurrentSet(inner)

// Atomic operations
s.Compute("elem", func(e string, exists bool) (string, bool) {
    return e, true  // add or keep
})

s.ComputeIfAbsent("elem", func(e string) (string, bool) {
    return e, true  // add if missing
})

s.ComputeIfPresent("elem", func(e string) (string, bool) {
    return e, false // remove if present
})
```

## Common Operations

```go
// Add/Remove
s.Add("x")
s.AddAll("x", "y", "z")
s.Remove("x")
s.RemoveAll("x", "y")
s.Clear()

// Query
s.Contains("x")
s.Size()
s.IsEmpty()
s.List()  // []E

// Set Operations
union := s.Union(other)
inter := s.Intersection(other)
diff := s.Difference(other)
symDiff := s.SymmetricDifference(other)

// Subset Relations
s.IsSubSet(other)
s.IsProperSubSet(other)
s.IsSuperSet(other)
s.IsProperSuperSet(other)
s.Equal(other)

// Power Set
subsets := s.SubSets()           // []Set
for sub := range s.IterSubSets() // iterator
```

## Iteration

```go
// Elements only
for elem := range s.Iter() {
    // ...
}

// With index
for i, elem := range s.Iter2() {
    // ...
}
```

## Freeze/Unfreeze

```go
// Create immutable snapshot
frozen := s.Freeze()

// Create mutable copy from immutable
mutable := frozen.Unfreeze()
```
