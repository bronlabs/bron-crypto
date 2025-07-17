package model

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base"
)

type WithSymbol interface {
	Symbol() Symbol
}

type Element[E any] base.Equatable[E]

type CarrierSet[E any] interface {
	WithSymbol
	Iter() iter.Seq[E]
}

func NewEmptyCarrierSet[E Element[E]]() CarrierSet[E] {
	return &emptySet[E]{}
}

type emptySet[E any] struct{}

func (*emptySet[E]) Symbol() Symbol {
	return EmptySymbol
}

func (e *emptySet[E]) Iter() iter.Seq[E] {
	return func(yield func(E) bool) {
		// No elements to iterate over
	}
}
