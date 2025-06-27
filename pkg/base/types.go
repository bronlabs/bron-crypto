package base

type Transparent[V any] interface {
	Value() V
}
type IncomparableTrait struct {
	_ [0]func()
}
type HashCode uint64

type Equatable[K any] interface {
	Equal(rhs K) bool
}
type Clonable[T any] interface {
	Clone() T
}

type Hashable[K any] interface {
	Equatable[K]
	HashCode() HashCode
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
