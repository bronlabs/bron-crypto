package base

import (
	"hash/fnv"
	"io"
)

type Transparent[V any] interface {
	Value() V
}
type IncomparableTrait struct {
	_ [0]func()
}
type HashCode uint64

func (hc HashCode) Combine(xs ...HashCode) HashCode {
	h := fnv.New64a()
	h.Write(hc.Bytes())
	for _, x := range xs {
		h.Write(x.Bytes())
	}
	return HashCode(h.Sum64())
}

func (hc HashCode) Bytes() []byte {
	return []byte{byte(hc)}
}

type Equatable[K any] interface {
	Equal(rhs K) bool
}
type Clonable[T any] interface {
	Clone() T
}

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

type BytesLike interface {
	Bytes() []byte
}

type BytesLikeFactory[E any] interface {
	FromBytes([]byte) (E, error)
	// If elemnts are atomic, ElementSize returns the **exact** number of bytes required to represent an element.
	// If elements are collections of atomic elements, ElementSize returns the size of an individual element.
	// If elements are variable size, ElementSize returns -1.
	ElementSize() int
}

type SamplableStructure[S, E any] interface {
	Random(prng io.Reader, opts ...func(S) error) (E, error)
}

func DeriveHashCode[T ~[]byte](xs ...T) HashCode {
	h := fnv.New64a()
	for _, x := range xs {
		h.Write(x)
	}
	return HashCode(h.Sum64())
}
