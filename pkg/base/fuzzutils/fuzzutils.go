package fuzzutils

type Underlyer = uint64

var MaxUnderlyerValue = Underlyer(100)

type AbstractAdapter[PreType, Type any] interface {
	Wrap(PreType) Type
	Unwrap(Type) PreType
	ZeroValue() Type
}

type Generator[T any] interface {
	Empty() T
	Prng() *Prng
	Reseed(seed1, seed2 uint64)
}

type generator[U, T any] struct {
	prng    *Prng
	adapter AbstractAdapter[U, T]
}

func (g *generator[U, T]) Empty() T {
	return g.adapter.ZeroValue()
}

func (g *generator[U, T]) Prng() *Prng {
	return g.prng
}

func (g *generator[U, T]) Reseed(seed1, seed2 uint64) {
	g.prng.Seed(seed1, seed2)
}
