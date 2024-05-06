package testutils2

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
)

type Map[K, V Object] any

type AbstractMapAdapter[T comparable, M Map[K, V], K, V Object] AbstractObjectAdapter[map[T]*ds.MapEntry[K, V], M]
type AbstractNativeMapAdapter[T comparable, M ~map[K]V, K comparable, V Object] AbstractObjectAdapter[map[T]T, M]

type MapAdapter[M Map[K, V], K, V Object] AbstractMapAdapter[UnderlyingGenerator, M, K, V]

type MapGenerator[M Map[K, V], K, V Object] interface {
	Generate(size int) M
	GenerateAnySize() M
	Keys() SliceGenerator[K]
	Values() SliceGenerator[V]
	Generator[M]
}

var _ MapGenerator[any, any, any] = (*MapGenerationSuite[any, any, any])(nil)

type MapGenerationSuite[M Map[K, V], K, V Object] struct {
	adapter MapAdapter[M, K, V]
	keys    SliceGenerator[K]
	values  SliceGenerator[V]
	prng    csprng.Seedable
}

func (m *MapGenerationSuite[M, K, V]) gen(preKeySize int) M {
	preKeys, err := RandomUnderlyerSlice(m.prng, preKeySize, true, false, false)
	if err != nil {
		panic(errs.WrapRandomSample(err, "could not sample underlyer slice"))
	}
	size := len(preKeys)
	keys := m.keys.Generate(size, true)
	values := m.values.Generate(size, false)

	out := map[UnderlyingGenerator]*ds.MapEntry[K, V]{}
	for i, pk := range preKeys {
		out[pk] = &ds.MapEntry[K, V]{
			Key:   keys[i],
			Value: values[i],
		}
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

func (m *MapGenerationSuite[M, K, V]) Keys() SliceGenerator[K] {
	return m.keys
}

func (m *MapGenerationSuite[M, K, V]) Values() SliceGenerator[V] {
	return m.values
}

func (m *MapGenerationSuite[M, K, V]) Empty() M {
	return m.adapter.Zero()
}

func (m *MapGenerationSuite[M, K, V]) Prng() csprng.Seedable {
	return m.prng
}

func NewMapGenerationSuite[M Map[K, V], K, V Object](mapAdapter MapAdapter[M, K, V], keysAdapter ObjectAdapter[K], valuesAdapter ObjectAdapter[V], prng csprng.Seedable) (*MapGenerationSuite[M, K, V], error) {
	if err := validateNewMapGenerationSuite(mapAdapter, keysAdapter, valuesAdapter, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid argument")
	}
	keysGenerator, err := NewSliceGenerationSuite(keysAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct key slice generator")
	}
	valuesGenerator, err := NewSliceGenerationSuite(valuesAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct value slice generator")
	}
	return &MapGenerationSuite[M, K, V]{
		adapter: mapAdapter,
		keys:    keysGenerator,
		values:  valuesGenerator,
		prng:    prng,
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
	keysGenerator, err := NewSliceGenerationSuite(keysAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct key slice generator")
	}
	valuesGenerator, err := NewSliceGenerationSuite(valuesAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct value slice generator")
	}
	mapAdapter := &NativeMapAdapter[M, K, V]{
		keys:   keysAdapter,
		values: valuesAdapter,
	}
	return &MapGenerationSuite[M, K, V]{
		adapter: mapAdapter,
		keys:    keysGenerator,
		values:  valuesGenerator,
		prng:    prng,
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
