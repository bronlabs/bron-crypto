package generators

import "golang.org/x/exp/constraints"

type sliceGenerator[L constraints.Unsigned, T any] struct {
	lenGen Generator[L]
	objGen Generator[T]
}

func NewSliceGenerator[L constraints.Unsigned, T any](lenGen Generator[L], objGen Generator[T]) Generator[[]T] {
	return &sliceGenerator[L, T]{
		lenGen,
		objGen,
	}
}

func (s *sliceGenerator[L, T]) Generate() []T {
	t := make([]T, int(s.lenGen.Generate()))
	for i := range t {
		t[i] = s.objGen.Generate()
	}

	return t
}
