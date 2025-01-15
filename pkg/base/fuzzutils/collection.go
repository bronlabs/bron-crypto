package fuzzutils

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type Collection[O Object] any
type CollectionUnderlyer = []ObjectUnderlyer

type CollectionAdapter[C Collection[O], O Object] AbstractAdapter[CollectionUnderlyer, C]

type SliceGenerator[S ~[]O, O Object] CollectionGenerator[S, O]
type CollectionGenerator[C Collection[O], O Object] interface {
	Generate(size int, distinct bool) C
	GenerateAnySize(distinct, nonEmpty bool) C
	Element() ObjectGenerator[O]
	SliceOfElements() SliceGenerator[[]O, O]

	Adapter() CollectionAdapter[C, O]
	Clone() CollectionGenerator[C, O]
	Generator[C]
}

var _ SliceGenerator[[]any, any] = (*collectionGenerator[[]any, any])(nil)
var _ CollectionGenerator[any, any] = (*collectionGenerator[any, any])(nil)

type collectionGenerator[C Collection[O], O Object] struct {
	generator[CollectionUnderlyer, C]
	element ObjectGenerator[O]
}

func (c collectionGenerator[C, O]) Generate(size int, distinct bool) C {
	if size == 0 {
		return c.Empty()
	}
	out := c.Prng().UnderlyerSlice(size, distinct, false, false)
	return c.adapter.Wrap((out))
}
func (c collectionGenerator[C, O]) GenerateAnySize(distinct, nonEmpty bool) C {
	size := c.Prng().Int(nonEmpty)
	out := c.Prng().UnderlyerSlice(size, distinct, false, false)
	return c.adapter.Wrap(out)
}
func (c collectionGenerator[C, O]) Element() ObjectGenerator[O] {
	return c.element
}
func (c collectionGenerator[C, O]) SliceOfElements() SliceGenerator[[]O, O] {
	return &collectionGenerator[[]O, O]{
		generator: generator[CollectionUnderlyer, []O]{
			prng: *c.Prng(),
			adapter: &SliceAdapter[[]O, O]{
				Adapter: c.Element().Adapter(),
			},
		},
		element: c.Element(),
	}
}
func (c collectionGenerator[C, O]) Adapter() CollectionAdapter[C, O] {
	return c.adapter
}
func (c collectionGenerator[C, O]) Clone() CollectionGenerator[C, O] {
	return collectionGenerator[C, O]{
		generator: generator[CollectionUnderlyer, C]{
			prng:    c.Prng().Clone(),
			adapter: c.adapter,
		},

		element: c.element.Clone(),
	}
}

func NewCollectionGenerator[C Collection[O], O Object](colAdapter CollectionAdapter[C, O], elementGenerator ObjectGenerator[O], prng *Prng) (CollectionGenerator[C, O], error) {
	if err := validateNewCollectionGenerator(colAdapter, elementGenerator, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}
	return &collectionGenerator[C, O]{
		generator: generator[CollectionUnderlyer, C]{
			prng:    *prng,
			adapter: colAdapter,
		},

		element: elementGenerator,
	}, nil
}

func validateNewCollectionGenerator[C Collection[O], O Object](collectionAdapter CollectionAdapter[C, O], elementGenerator ObjectGenerator[O], prng *Prng) error {
	if collectionAdapter == nil {
		return errs.NewIsNil("collection adapter")
	}
	if elementGenerator == nil {
		return errs.NewIsNil("element generator")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}

func NewSliceGenerator[S ~[]O, O Object](objectAdapter ObjectAdapter[O], prng *Prng) (CollectionGenerator[S, O], error) {
	objectGenerator, err := NewObjectGenerator(objectAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct object generation suite")
	}
	sliceAdapter := &SliceAdapter[S, O]{
		Adapter: objectAdapter,
	}
	return &collectionGenerator[S, O]{
		generator: generator[CollectionUnderlyer, S]{
			prng:    *prng,
			adapter: sliceAdapter,
		},
		element: objectGenerator,
	}, nil
}
