package option

type Option[T any] struct {
	value  T
	isFull bool
}

func Some[T any](value T) Option[T] {
	return Option[T]{value: value, isFull: true}
}

func None[T any]() Option[T] {
	return Option[T]{isFull: false}
}

func (s *Option[T]) Get() T {
	if s.isFull {
		return s.value
	} else {
		panic("option is empty")
	}
}

func (s *Option[T]) GetOrElse(other T) T {
	if s.isFull {
		return s.value
	} else {
		return other
	}
}

func (s *Option[_]) IsEmpty() bool {
	return !s.isFull
}
