// Package bitset provides efficient bitset implementations for unsigned integer
// sets with elements in the range [1, 64].
//
// A bitset uses a single uint64 as a bitmask where bit position i (0-63)
// represents whether element i+1 is present in the set. This enables
// extremely fast set operations using bitwise operations.
//
// # Types
//
// BitSet[U] is the mutable variant with pointer receivers, implementing
// ds.MutableSet[U] where U is any unsigned integer type (uint, uint8, uint16,
// uint32, uint64, or uintptr). Use this when you need to modify the set in place.
//
// ImmutableBitSet[U] is the immutable variant with value receivers, implementing
// ds.Set[U]. All operations return new values without modifying the original,
// leveraging Go's value semantics for guaranteed immutability.
//
// # Element Range
//
// Both types support elements in the range [1, 64]. Elements are 1-indexed
// to match common usage patterns (e.g., party IDs starting at 1). Operations
// on elements outside this range will panic. The generic parameter U allows
// using different unsigned types (uint8, uint16, uint32, uint64) while maintaining
// the same 64-element capacity.
//
// # Performance
//
// All operations are O(1) except:
//   - Iteration: O(n) where n is the number of elements (not 64!)
//   - SubSet generation: O(2^n) where n is the number of elements
//
// Memory: Both types use exactly 8 bytes (1 uint64)
//
// # Usage Example
//
//	// Mutable set with uint64 elements
//	s := bitset.NewBitSet[uint64](1, 5, 10)
//	s.Add(15)
//	s.Remove(5)
//	frozen := s.Freeze()
//
//	// Immutable set with uint32 elements
//	s1 := bitset.NewImmutableBitSet[uint32](1, 2, 3)
//	s2 := bitset.NewImmutableBitSet[uint32](3, 4, 5)
//	union := s1.Union(s2)  // s1 and s2 unchanged
//
// # Bitwise Operations
//
// The implementation uses efficient bitwise operations:
//   - Union: s | other
//   - Intersection: s & other
//   - Difference: s &^ other
//   - Symmetric Difference: s ^ other
//   - IsSubSet: (s &^ other) == 0
package bitset
