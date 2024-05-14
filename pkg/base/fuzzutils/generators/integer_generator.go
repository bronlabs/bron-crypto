package generators

import (
	"golang.org/x/exp/constraints"
	randv2 "math/rand/v2"
)

type integerGenerator[T constraints.Integer] struct {
	prng *randv2.Rand
}

type rangeIntegerGenerator[T constraints.Integer] struct {
	low, high T
	prng      *randv2.Rand
}

func NewIntegerGenerator[T constraints.Integer](prng randv2.Source) Generator[T] {
	return &integerGenerator[T]{
		prng: randv2.New(prng),
	}
}

func (i *integerGenerator[T]) Generate() T {
	return T(randv2.Uint64())
}

func NewRangeIntegerGenerator[T constraints.Integer](prng randv2.Source, low, high T) Generator[T] {
	return &rangeIntegerGenerator[T]{
		low:  low,
		high: high,
		prng: randv2.New(prng),
	}
}

func (r *rangeIntegerGenerator[T]) Generate() T {
	return r.low + T(r.prng.Uint64N(uint64(r.high-r.low)))
}
