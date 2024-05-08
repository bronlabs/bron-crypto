package testutils2

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
)

type Collection[O Object] any
type CollectionUnderlyer = []ObjectUnderlyer

type CollectionAdapter[C Collection[O], O Object] AbstractAdapter[CollectionUnderlyer, C]

type SliceGenerator[S ~[]O, O Object] CollectionGenerator[S, O]
type CollectionGenerator[C Collection[O], O Object] interface {
	Generate(size int, distinct bool) C
	GenerateAnySize(distinct bool) C
	Element() ObjectGenerator[O]
	Generator[C]
}

var _ SliceGenerator[[]any, any] = (*CollectionGenerationSuite[[]any, any])(nil)
var _ CollectionGenerator[any, any] = (*CollectionGenerationSuite[any, any])(nil)

type CollectionGenerationSuite[C Collection[O], O Object] struct {
	GeneratorTrait[CollectionUnderlyer, C]
	element ObjectGenerator[O]
}

func (c *CollectionGenerationSuite[C, O]) Generate(size int, distinct bool) C {
	if size < 0 {
		panic(errs.NewArgument("size < 0"))
	}
	if distinct && size > int(MaxUnderlyerValue) {
		panic(errs.NewArgument("distinct and size > MaxUnderLyeer (%d)", MaxUnderlyerValue))
	}
	if size == 0 {
		return c.Empty()
	}
	out, err := RandomUnderlyerSlice[CollectionUnderlyer, ObjectUnderlyer](c.prng, size, distinct, false, false)
	if err != nil {
		panic(errs.WrapRandomSample(err, "could not sample underlyer slice"))
	}
	return c.adapter.Wrap((out))
}
func (c *CollectionGenerationSuite[C, O]) GenerateAnySize(distinct bool) C {
	out, err := RandomUnderlyerSlice[CollectionUnderlyer, ObjectUnderlyer](c.prng, -1, distinct, false, false)
	if err != nil {
		panic(errs.WrapRandomSample(err, "could not sample underlyer slice"))
	}
	return c.adapter.Wrap(out)
}
func (c *CollectionGenerationSuite[C, O]) Element() ObjectGenerator[O] {
	return c.element
}

func NewCollectionGenerationSuite[C Collection[O], O Object](colAdapter CollectionAdapter[C, O], elementGenerator ObjectGenerator[O], prng csprng.Seedable) (*CollectionGenerationSuite[C, O], error) {
	if err := validateNewCollectionGenerationSuite(colAdapter, elementGenerator, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}
	return &CollectionGenerationSuite[C, O]{
		GeneratorTrait: GeneratorTrait[CollectionUnderlyer, C]{
			prng:    prng,
			adapter: colAdapter,
		},

		element: elementGenerator,
	}, nil
}

func validateNewCollectionGenerationSuite[C Collection[O], O Object](collectionAdapter CollectionAdapter[C, O], elementGenerator ObjectGenerator[O], prng csprng.Seedable) error {
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

func NewSliceGenerationSuite[S ~[]O, O Object](objectAdapter ObjectAdapter[O], prng csprng.Seedable) (*CollectionGenerationSuite[S, O], error) {
	objectGenerator, err := NewObjectGenerationSuite(objectAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct object generation suite")
	}
	sliceAdapter := &SliceAdapter[S, O]{
		objectAdapter: objectAdapter,
	}
	return &CollectionGenerationSuite[S, O]{
		GeneratorTrait: GeneratorTrait[CollectionUnderlyer, S]{
			prng:    prng,
			adapter: sliceAdapter,
		},
		element: objectGenerator,
	}, nil
}
