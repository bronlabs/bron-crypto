package generators

import randv2 "math/rand/v2"

type sliceElementGenerator[T any, U ~[]T] struct {
	slice U
	prng  *randv2.Rand
}

func NewSliceElementGenerator[T any, U ~[]T](prng randv2.Source, slice U) Generator[T] {
	return &sliceElementGenerator[T, U]{
		slice: slice,
		prng:  randv2.New(prng),
	}
}

func (s *sliceElementGenerator[T, U]) Generate() T {
	idx := int(s.prng.UintN(uint(len(s.slice))))
	return s.slice[idx]
}
