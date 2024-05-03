package testutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"pgregory.net/rapid"
)

type Collection[E any] any

type AbstractCollectionAdapters[T comparable, C Collection[E], E any] interface {
	Element(T) E
	UnwrapElement(E) T
	Collection([]T) C
	UnwrapCollection(C) []T
	Empty() C
}

type CollectionAdapters[C Collection[E], E any] AbstractCollectionAdapters[uint, C, E]

type CollectionPropertyTester[C Collection[E], E any] struct {
	Adapters            CollectionAdapters[C, E]
	MaxNumberOfElements int
	BoundedIntGenerator *rapid.Generator[int]
}

func (pt *CollectionPropertyTester[C, E]) genElements(minLen, maxLen int, distinct bool) *rapid.Generator[[]E] {
	return rapid.Map(
		UintsGenerator(minLen, maxLen, distinct),
		func(xs []uint) []E {
			out := make([]E, len(xs))
			for i, x := range xs {
				out[i] = pt.Adapters.Element(x)
			}
			return out
		},
	)
}

func (pt *CollectionPropertyTester[C, E]) genCol(minLen, maxLen int) *rapid.Generator[C] {
	return rapid.Map(
		UintsGenerator(minLen, maxLen, true),
		pt.Adapters.Collection,
	)
}

func (pt *CollectionPropertyTester[C, E]) VariableSizeGenerator() *rapid.Generator[C] {
	return pt.genCol(1, pt.MaxNumberOfElements)
}

func (pt *CollectionPropertyTester[C, E]) FixedSizeGenerator(positiveSize int) *rapid.Generator[C] {
	if positiveSize < 1 {
		panic(errs.NewFailed("size %d < 1", positiveSize))
	}
	return pt.genCol(positiveSize, positiveSize)
}

func (pt *CollectionPropertyTester[C, E]) ElementGenerator() *rapid.Generator[E] {
	return rapid.Map(
		pt.BoundedIntGenerator,
		func(x int) E {
			return pt.Adapters.Element(uint(x))
		},
	)
}

func (pt *CollectionPropertyTester[C, E]) FixedSizeElementSliceGenerator(positiveSize int, distinct bool) *rapid.Generator[[]E] {
	if positiveSize < 1 {
		panic(errs.NewFailed("size %d < 1", positiveSize))
	}
	return pt.genElements(positiveSize, positiveSize, distinct)
}

func (pt *CollectionPropertyTester[C, E]) VariableSizeElementSliceGenerator(distinct bool) *rapid.Generator[[]E] {
	return pt.genElements(1, pt.MaxNumberOfElements, distinct)
}

func NewCollectionPropertyTester[C Collection[E], E any](adapters CollectionAdapters[C, E], maxNumberOfElements uint) (*CollectionPropertyTester[C, E], error) {
	if err := validateNewCollectionPropertyTesterInput(adapters, maxNumberOfElements); err != nil {
		return nil, errs.WrapValidation(err, "could not validate arguments")
	}
	return &CollectionPropertyTester[C, E]{
		Adapters:            adapters,
		MaxNumberOfElements: int(maxNumberOfElements),
		BoundedIntGenerator: rapid.IntRange(1, int(maxNumberOfElements)),
	}, nil
}

func validateNewCollectionPropertyTesterInput[C Collection[E], E any](adapters CollectionAdapters[C, E], maxNumberOfElements uint) error {
	if adapters == nil {
		return errs.NewIsNil("adapters")
	}
	if maxNumberOfElements == 0 {
		return errs.NewIsZero("maxNumberOfElements")
	}
	return nil
}
