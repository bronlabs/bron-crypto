package utils_test

import (
	"testing"
)

type Iterator[T any] interface {
	Next() T
	HasNext() bool
}

type Iterable[T any] interface {
	Iterator() Iterator[T]
}

type Container struct {
	Values []string
}

var _ Iterable[string] = (*Container)(nil)

func (c *Container) Iterator() Iterator[string] {
	return &containerIterator{
		next:      0,
		container: c,
	}
}

type containerIterator struct {
	next      int
	container *Container
}

var _ Iterator[string] = (*containerIterator)(nil)

func (i *containerIterator) Next() string {
	v := i.container.Values[i.next]
	i.next++
	return v
}

func (i *containerIterator) HasNext() bool {
	return i.next < len(i.container.Values)
}

func Test_Iterator(t *testing.T) {
	theContainer := &Container{
		Values: []string{"foo", "bar", "42"},
	}

	for iter := theContainer.Iterator(); iter.HasNext(); {
		v := iter.Next()
		println(v)
	}
}
