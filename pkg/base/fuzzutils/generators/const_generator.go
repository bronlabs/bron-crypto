package generators

type constGenerator[T any] struct {
	value T
}

func NewConstGenerator[T any](value T) Generator[T] {
	return &constGenerator[T]{
		value: value,
	}
}

func (c *constGenerator[T]) Generate() T {
	return c.value
}
