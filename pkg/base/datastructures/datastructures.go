package datastructures

import (
	"encoding/binary"
	"hash/fnv"
)

// HashCode represents a 64-bit hash code.
type HashCode uint64

// Combine combines the current HashCode with additional HashCodes and returns a new HashCode.
func (hc HashCode) Combine(xs ...HashCode) HashCode {
	h := fnv.New64a()
	h.Write(hc.Bytes())
	for _, x := range xs {
		h.Write(x.Bytes())
	}
	return HashCode(h.Sum64())
}

// Bytes returns the byte representation of the HashCode in little-endian order.
func (hc HashCode) Bytes() []byte {
	return binary.LittleEndian.AppendUint64(nil, uint64(hc))
}

// DeriveHashCode derives a HashCode from one or more byte slices.
func DeriveHashCode[T ~[]byte](xs ...T) HashCode {
	h := fnv.New64a()
	for _, x := range xs {
		h.Write(x)
	}
	return HashCode(h.Sum64())
}

// Equatable represents a type that can be compared for equality.
type Equatable[T any] interface {
	// Equal checks if the receiver is equal to rhs.
	Equal(rhs T) bool
}

// Clonable represents a type that can be cloned.
type Clonable[T any] interface {
	// Clone creates and returns a deep copy of the receiver.
	Clone() T
}

// Hashable represents a type that can be hashed and compared for equality.
type Hashable[T any] interface {
	Equatable[T]
	// HashCode returns the hash code of the receiver.
	HashCode() HashCode
}
