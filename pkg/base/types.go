package base

import (
	"encoding/binary"
	"hash/fnv"
)

type Transparent[V any] interface {
	Value() V
}
type HashCode uint64

func (hc HashCode) Combine(xs ...HashCode) HashCode {
	// TODO: change to XOR, maybe measure its difference
	h := fnv.New64a()
	h.Write(hc.Bytes())
	for _, x := range xs {
		h.Write(x.Bytes())
	}
	return HashCode(h.Sum64())
}

func (hc HashCode) Bytes() []byte {
	return binary.LittleEndian.AppendUint64(nil, uint64(hc))
}

type Equatable[K any] interface {
	Equal(rhs K) bool
}
type Clonable[T any] interface {
	Clone() T
}

// TODO: remove embed in Hashable
type WithHashCode interface {
	HashCode() HashCode
}

type Hashable[K any] interface {
	Equatable[K]
	WithHashCode
}

type HashableStructure[E any] interface {
	Hash([]byte) (E, error)
}

// TODO: move to transcripts package
type BytesLike interface {
	Bytes() []byte
}

// TODO: move back to algebra, and only keep element size
type BytesLikeFactory[E any] interface {
	FromBytes([]byte) (E, error)
	// TODO: review below (Mateusz) and prove in no where this would be used at a generic level.

	// If elemnts are atomic, ElementSize returns the **exact** number of bytes (implementation-dependent) required to represent an element.
	// If elements are collections of atomic elements, ElementSize returns the size of an individual element.
	// If elements are variable size, ElementSize returns -1.
	ElementSize() int
}

// TODO: remove. Maybe move to experimental.
// type SamplableStructure[S, E any] interface {
// 	Random(prng io.Reader, opts ...func(S) error) (E, error)
// }.

func DeriveHashCode[T ~[]byte](xs ...T) HashCode {
	h := fnv.New64a()
	for _, x := range xs {
		h.Write(x)
	}
	return HashCode(h.Sum64())
}
