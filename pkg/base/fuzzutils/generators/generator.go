package generators

type Generator[T any] interface {
	Generate() T
}

type constantGenerator[T any] struct{}

type fixedLenSliceGenerator[T any] struct {
	size            uint
	objectGenerator ObjectGenerator[T]
}

func NewFixedLenSliceGenerator[T any](objectGenerator ObjectGenerator[T], size uint) Generator[[]T] {
	return &fixedLenSliceGenerator[T]{
		size:            size,
		objectGenerator: objectGenerator,
	}
}

func (s *fixedLenSliceGenerator[T]) Prng() *FuzzPrng {
	return s.objectGenerator.Prng()
}

func (s *fixedLenSliceGenerator[T]) Generate() []T {
	t := make([]T, s.size)
	for i := range t {
		t[i] = s.objectGenerator.Generate()
	}

	return t
}
