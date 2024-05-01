package datastructures

type Incomparable [0]func()

type Equatable[K any] interface {
	Equal(rhs K) bool
}

type Hashable[K any] interface {
	Equatable[K]
	HashCode() uint64
}
