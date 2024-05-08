package testutils2

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
)

type Map[K, V Object] any
type MapUnderlyer = map[ObjectUnderlyer]ObjectUnderlyer

type MapAdapter[M Map[K, V], K, V Object] AbstractAdapter[MapUnderlyer, M]

var _ MapGenerator[any, any, any] = (*MapGenerationSuite[any, any, any])(nil)

type MapGenerator[M Map[K, V], K, V Object] interface {
	Generate(size int) M
	GenerateAnySize() M
	Keys() SliceGenerator[[]K, K]
	Values() SliceGenerator[[]V, V]
	Generator[M]
}

type MapGenerationSuite[M Map[K, V], K, V Object] struct {
	GeneratorTrait[MapUnderlyer, M]
	keys   SliceGenerator[[]K, K]
	values SliceGenerator[[]V, V]
}

func (m *MapGenerationSuite[M, K, V]) gen(keysSize int) M {
	keysUnwrapped, err := RandomUnderlyerSlice[CollectionUnderlyer, ObjectUnderlyer](m.prng, keysSize, true, false, false)
	if err != nil {
		panic(errs.WrapRandomSample(err, "could not sample underlyer keys"))
	}
	sampleSize := len(keysUnwrapped)
	valuesUnwrapped, err := RandomUnderlyerSlice[CollectionUnderlyer, ObjectUnderlyer](m.prng, sampleSize, false, false, false)
	if err != nil {
		panic(errs.WrapRandomSample(err, "could not sample underlyer values"))
	}
	out := MapUnderlyer{}
	for i := range sampleSize {
		out[keysUnwrapped[i]] = valuesUnwrapped[i]
	}
	return m.adapter.Wrap(out)
}

func (m *MapGenerationSuite[M, K, V]) Generate(size int) M {
	if size < 1 {
		panic(errs.NewArgument("size < 1"))
	}
	return m.gen(size)
}

func (m *MapGenerationSuite[M, K, V]) GenerateAnySize() M {
	return m.gen(-1)
}

func (m *MapGenerationSuite[M, K, V]) Keys() SliceGenerator[[]K, K] {
	return m.keys
}

func (m *MapGenerationSuite[M, K, V]) Values() SliceGenerator[[]V, V] {
	return m.values
}

func NewMapGenerationSuite[M Map[K, V], K, V Object](mapAdapter MapAdapter[M, K, V], keysAdapter ObjectAdapter[K], valuesAdapter ObjectAdapter[V], prng csprng.Seedable) (*MapGenerationSuite[M, K, V], error) {
	if err := validateNewMapGenerationSuite(mapAdapter, keysAdapter, valuesAdapter, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid argument")
	}
	keysGenerator, err := NewSliceGenerationSuite[[]K](keysAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct key slice generator")
	}
	valuesGenerator, err := NewSliceGenerationSuite[[]V](valuesAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct value slice generator")
	}
	return &MapGenerationSuite[M, K, V]{
		GeneratorTrait: GeneratorTrait[MapUnderlyer, M]{
			adapter: mapAdapter,
			prng:    prng,
		},
		keys:   keysGenerator,
		values: valuesGenerator,
	}, nil
}

func validateNewMapGenerationSuite[M Map[K, V], K, V Object](mapAdapter MapAdapter[M, K, V], keysAdapter ObjectAdapter[K], valuesAdapter ObjectAdapter[V], prng csprng.Seedable) error {
	if mapAdapter == nil {
		return errs.NewIsNil("mapAdapter")
	}
	if keysAdapter == nil {
		return errs.NewIsNil("keysAdapter")
	}
	if valuesAdapter == nil {
		return errs.NewIsNil("valuesAdapter")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}

func NewNativeMapGenerationSuite[M ~map[K]V, K comparable, V Object](keysAdapter ObjectAdapter[K], valuesAdapter ObjectAdapter[V], prng csprng.Seedable) (*MapGenerationSuite[M, K, V], error) {
	if err := validateNewNativeMapGenerationSuite[M](keysAdapter, valuesAdapter, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid argument")
	}
	keysGenerator, err := NewSliceGenerationSuite[[]K](keysAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct key slice generator")
	}
	valuesGenerator, err := NewSliceGenerationSuite[[]V](valuesAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct value slice generator")
	}
	mapAdapter := &NativeMapAdapter[M, K, V]{
		keys:   keysAdapter,
		values: valuesAdapter,
	}
	return &MapGenerationSuite[M, K, V]{
		GeneratorTrait: GeneratorTrait[MapUnderlyer, M]{
			adapter: mapAdapter,
			prng:    prng,
		},
		keys:   keysGenerator,
		values: valuesGenerator,
	}, nil
}

func validateNewNativeMapGenerationSuite[M ~map[K]V, K comparable, V Object](keysAdapter ObjectAdapter[K], valuesAdapter ObjectAdapter[V], prng csprng.Seedable) error {
	if keysAdapter == nil {
		return errs.NewIsNil("keysAdapter")
	}
	if valuesAdapter == nil {
		return errs.NewIsNil("valuesAdapter")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}
