package base

import ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"

type (
	// HashCode represents a 64-bit hash code.
	HashCode = ds.HashCode
	// Equatable represents a type that can be compared for equality.
	Equatable[T any] = ds.Equatable[T]
	// Clonable represents a type that can be cloned.
	Clonable[T any] = ds.Clonable[T]
	// Hashable represents a type that can be hashed and compared for equality.
	Hashable[T any] = ds.Hashable[T]
)

// DeriveHashCode derives a HashCode from one or more byte slices.
func DeriveHashCode[T ~[]byte](xs ...T) HashCode {
	return ds.DeriveHashCode(xs...)
}

// Transparent represents a type that can expose an underlying value of type V.
type Transparent[V any] interface {
	Value() V
}

// HashableStructure represents a structure that can hash byte slices into elements of type E.
type HashableStructure[E any] interface {
	// Hash hashes the input byte slice and returns an element of type E.
	Hash([]byte) (E, error)
}

// BytesLike represents types that can provide a byte slice representation.
type BytesLike interface {
	// Bytes returns the byte slice representation of the receiver.
	Bytes() []byte
}

// BytesLikeFactory represents a factory for creating elements of type E from byte slices.
type BytesLikeFactory[E any] interface {
	// FromBytes creates an element of type E from the given byte slice.
	FromBytes([]byte) (E, error)
	// If elemnts are atomic, ElementSize returns the **exact** number of bytes (implementation-dependent) required to represent an element.
	// If elements are collections of atomic elements, ElementSize returns the size of an individual element.
	// If elements are variable size, ElementSize returns -1.
	ElementSize() int
}
