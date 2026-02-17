# BitSet

Efficient generic bitset implementation for unsigned integer sets with elements in the range [1, 64].

## Overview

This package provides two generic bitset implementations:

- **`BitSet[U]`**: Mutable bitset with pointer receivers (`ds.MutableSet[U]`)
- **`ImmutableBitSet[U]`**: Immutable bitset with value receivers (`ds.Set[U]`)

where `U` is any unsigned integer type (`uint`, `uint8`, `uint16`, `uint32`, `uint64`, or `uintptr`).

Both types use a single `uint64` as a bitmask, where bit position i (0-63) represents whether element i+1 is in the set.

## Features

- **Compact**: 8 bytes per set (1 uint64)
- **Fast**: O(1) for all operations except iteration and subset generation
- **Safe**: Value semantics ensure `ImmutableBitSet` cannot be accidentally modified
- **Complete**: Implements full `ds.MutableSet[uint64]` and `ds.Set[uint64]` interfaces

## Usage

### Mutable BitSet

```go
import "github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"

// Create a new mutable bitset with uint64 elements
s := bitset.NewBitSet[uint64](1, 5, 10)

// Add and remove elements
s.Add(15)
s.Remove(5)

// Set operations
s2 := bitset.NewBitSet[uint64](10, 15, 20)
union := s.Union(s2)
intersection := s.Intersection(s2)

// Check membership
if s.Contains(10) {
    // ...
}

// Iterate over elements (in order)
for e := range s.Iter() {
    fmt.Println(e)  // 1, 10, 15
}

// Convert to immutable
frozen := s.Freeze()
```

### Immutable BitSet

```go
// Create immutable bitset with uint32 elements
s1 := bitset.NewImmutableBitSet[uint32](1, 2, 3)
s2 := bitset.NewImmutableBitSet[uint32](3, 4, 5)

// All operations return new values
union := s1.Union(s2)              // ImmutableBitSet{1,2,3,4,5}
intersection := s1.Intersection(s2) // ImmutableBitSet{3}
difference := s1.Difference(s2)     // ImmutableBitSet{1,2}

// s1 and s2 are unchanged
fmt.Println(s1.Size()) // 3
fmt.Println(s2.Size()) // 3

// Convert to mutable
mutable := s1.Unfreeze()
mutable.Add(10)
// s1 is still unchanged
```

### Subset Operations

```go
s := bitset.NewBitSet[uint64](1, 2, 3, 4)

// Generate all subsets (power set)
subsets := s.SubSets()  // 16 subsets (2^4)

// Iterate over subsets
for subset := range s.IterSubSets() {
    fmt.Println(subset.List())
}

// Check subset relations
s1 := bitset.NewBitSet[uint64](1, 2)
s2 := bitset.NewBitSet[uint64](1, 2, 3)

s1.IsSubSet(s2)        // true
s1.IsProperSubSet(s2)  // true
s2.IsSuperSet(s1)      // true
```

### Using Different Unsigned Types

```go
// BitSet works with any unsigned integer type
s8 := bitset.NewBitSet[uint8](1, 2, 3)
s16 := bitset.NewBitSet[uint16](10, 20, 30)
s32 := bitset.NewBitSet[uint32](5, 15, 25)
s64 := bitset.NewBitSet[uint64](1, 32, 64)

// All have the same [1, 64] range limit regardless of type parameter
s8.Add(64)  // OK
s8.Add(65)  // Panic: element out of range
```

## Element Range

Elements must be in the range **[1, 64]** regardless of the type parameter `U`. This 1-indexed design matches common usage patterns where party IDs or similar identifiers start at 1.

The generic type parameter `U` can be any unsigned integer type (`uint`, `uint8`, `uint16`, `uint32`, `uint64`, `uintptr`), but the element range is always [1, 64]. For example, `BitSet[uint8]` still supports elements 1-64, not just 1-255.

Operations on elements outside this range will panic:

```go
s := bitset.NewBitSet[uint64]()
s.Add(0)   // panic: element out of range
s.Add(65)  // panic: element out of range
s.Add(32)  // OK

// Type parameter doesn't affect range
s8 := bitset.NewBitSet[uint8]()
s8.Add(64)  // OK - range is still [1, 64]
s8.Add(200) // Panic - even though uint8 can hold 200
```

## Implementation Details

### Representation

Element `e` (1 ≤ e ≤ 64) is stored in bit position `e-1`:

```
Element:  1  2  3  4  ... 64
Bit:      0  1  2  3  ... 63
```

For example, the set {1, 3, 5} is represented as:
```
Binary: 0b...010101
        bit: 4 3 2 1 0
        element: 5 4 3 2 1
```

### Bitwise Operations

All set operations use efficient bitwise operations:

| Operation | Formula | Complexity |
|-----------|---------|------------|
| Union | `s \| other` | O(1) |
| Intersection | `s & other` | O(1) |
| Difference | `s &^ other` | O(1) |
| Symmetric Difference | `s ^ other` | O(1) |
| IsSubSet | `(s &^ other) == 0` | O(1) |
| Contains | `(s & (1 << (e-1))) != 0` | O(1) |
| Size | `bits.OnesCount64(s)` | O(1) |

### Subset Iteration

The `IterSubSets` method uses the standard submask iteration algorithm:

```go
sub := s
for {
    yield(sub)
    if sub == 0 { break }
    sub = (sub - 1) & s
}
```

This visits all 2^n subsets efficiently without recursion or allocations.

## Performance

- **Memory**: 8 bytes per set
- **Add/Remove/Contains**: ~1 ns (single bitwise operation)
- **Union/Intersection/Difference**: ~1 ns (single bitwise operation)
- **Iteration**: ~10 ns per element
- **Subset generation**: 2^n operations for n elements

## Thread Safety

Neither `BitSet` nor `ImmutableBitSet` is thread-safe. For concurrent access:
- Use external synchronization (mutex)
- Or use the `ImmutableBitSet` with concurrent read-only access

## Comparison with Other Set Types

| Feature | BitSet | hashset.MutableComparableSet |
|---------|--------|------------------------------|
| Memory | 8 bytes | ~48 bytes + 8 per element |
| Add/Remove | O(1), ~1 ns | O(1), ~50 ns |
| Contains | O(1), ~1 ns | O(1), ~20 ns |
| Max elements | 64 | unlimited |
| Element type | uint64 [1,64] | any comparable |

Use BitSet when:
- Elements are in range [1, 64]
- Performance is critical
- Memory usage matters
- Working with small party sets (common in MPC protocols)

Use hashset when:
- Need more than 64 elements
- Elements are not in [1, 64] range
- Need arbitrary comparable types
