package base

import (
	"encoding/binary"
	"hash/fnv"
)

// Transparent represents a type that can expose an underlying value of type V.
type Transparent[V any] interface {
	Value() V
}

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

// Equatable represents a type that can be compared for equality.
type Equatable[K any] interface {
	// Equal checks if the receiver is equal to rhs.
	Equal(rhs K) bool
}

// Clonable represents a type that can be cloned.
type Clonable[T any] interface {
	// Clone creates and returns a deep copy of the receiver.
	Clone() T
}

// Hashable represents a type that can be hashed and compared for equality.
type Hashable[K any] interface {
	Equatable[K]
	// HashCode returns the hash code of the receiver.
	HashCode() HashCode
}

// HashableStructure represents a structure that can hash byte slices into elements of type E.
type HashableStructure[E any] interface {
	// Hash hashes the input byte slice and returns an element of type E.
	Hash([]byte) (E, error)
}

// BytesLike represents types that can provide a byte slice representation.
// TODO: move to transcripts package
type BytesLike interface {
	// Bytes returns the byte slice representation of the receiver.
	Bytes() []byte
}

// BytesLikeFactory represents a factory for creating elements of type E from byte slices.
// TODO: move back to algebra, and only keep element size
type BytesLikeFactory[E any] interface {
	// FromBytes creates an element of type E from the given byte slice.
	FromBytes([]byte) (E, error)
	// If elemnts are atomic, ElementSize returns the **exact** number of bytes (implementation-dependent) required to represent an element.
	// If elements are collections of atomic elements, ElementSize returns the size of an individual element.
	// If elements are variable size, ElementSize returns -1.
	ElementSize() int
}

// DeriveHashCode derives a HashCode from one or more byte slices.
func DeriveHashCode[T ~[]byte](xs ...T) HashCode {
	h := fnv.New64a()
	for _, x := range xs {
		h.Write(x)
	}
	return HashCode(h.Sum64())
}
