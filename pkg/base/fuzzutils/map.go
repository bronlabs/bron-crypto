package fuzzutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Map[K, V Object] any
type MapUnderlyer = map[ObjectUnderlyer]ObjectUnderlyer

type MapAdapter[M Map[K, V], K, V Object] AbstractAdapter[MapUnderlyer, M]

var _ MapGenerator[any, any, any] = (*mapGenerator[any, any, any])(nil)

type MapGenerator[M Map[K, V], K, V Object] interface {
	Generate(size int) M
	GenerateAnySize() M
	Keys() SliceGenerator[[]K, K]
	Values() SliceGenerator[[]V, V]

	Adapter() MapAdapter[M, K, V]
	Clone() MapGenerator[M, K, V]
	Generator[M]
}

type mapGenerator[M Map[K, V], K, V Object] struct {
	generator[MapUnderlyer, M]
	keys   SliceGenerator[[]K, K]
	values SliceGenerator[[]V, V]
}

func (m mapGenerator[M, K, V]) gen(keysSize int) M {
	keysUnwrapped := m.Prng().UnderlyerSlice(keysSize, true, false, false)
	sampleSize := len(keysUnwrapped)
	valuesUnwrapped := m.Prng().UnderlyerSlice(sampleSize, false, false, false)
	out := MapUnderlyer{}
	for i := range sampleSize {
		out[keysUnwrapped[i]] = valuesUnwrapped[i]
	}
	return m.adapter.Wrap(out)
}

func (m mapGenerator[M, K, V]) Generate(size int) M {
	return m.gen(size)
}

func (m mapGenerator[M, K, V]) GenerateAnySize() M {
	return m.gen(-1)
}

func (m mapGenerator[M, K, V]) Keys() SliceGenerator[[]K, K] {
	return m.keys
}

func (m mapGenerator[M, K, V]) Values() SliceGenerator[[]V, V] {
	return m.values
}
func (m mapGenerator[M, K, V]) Adapter() MapAdapter[M, K, V] {
	return m.adapter
}
func (m mapGenerator[M, K, V]) Clone() MapGenerator[M, K, V] {
	return mapGenerator[M, K, V]{
		generator: generator[MapUnderlyer, M]{
			adapter: m.adapter,
			prng:    m.Prng().Clone(),
		},
		keys:   m.Keys().Clone(),
		values: m.Values().Clone(),
	}
}

func NewMapGenerator[M Map[K, V], K, V Object](mapAdapter MapAdapter[M, K, V], keysAdapter ObjectAdapter[K], valuesAdapter ObjectAdapter[V], prng *Prng) (MapGenerator[M, K, V], error) {
	if err := validateNewMapGenerator(mapAdapter, keysAdapter, valuesAdapter, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid argument")
	}
	keysGenerator, err := NewSliceGenerator[[]K](keysAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct key slice generator")
	}
	valuesGenerator, err := NewSliceGenerator[[]V](valuesAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct value slice generator")
	}
	return &mapGenerator[M, K, V]{
		generator: generator[MapUnderlyer, M]{
			adapter: mapAdapter,
			prng:    *prng,
		},
		keys:   keysGenerator,
		values: valuesGenerator,
	}, nil
}

func validateNewMapGenerator[M Map[K, V], K, V Object](mapAdapter MapAdapter[M, K, V], keysAdapter ObjectAdapter[K], valuesAdapter ObjectAdapter[V], prng *Prng) error {
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

func NewNativeMapGenerator[M ~map[K]V, K comparable, V Object](keysAdapter ObjectAdapter[K], valuesAdapter ObjectAdapter[V], prng *Prng) (MapGenerator[M, K, V], error) {
	if err := validateNewNativeMapGenerator[M](keysAdapter, valuesAdapter, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid argument")
	}
	keysGenerator, err := NewSliceGenerator[[]K](keysAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct key slice generator")
	}
	valuesGenerator, err := NewSliceGenerator[[]V](valuesAdapter, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consturct value slice generator")
	}
	mapAdapter := &NativeMapAdapter[M, K, V]{
		KeysAdapter:   keysAdapter,
		ValuesAdapter: valuesAdapter,
	}
	return &mapGenerator[M, K, V]{
		generator: generator[MapUnderlyer, M]{
			adapter: mapAdapter,
			prng:    *prng,
		},
		keys:   keysGenerator,
		values: valuesGenerator,
	}, nil
}

func validateNewNativeMapGenerator[M ~map[K]V, K comparable, V Object](keysAdapter ObjectAdapter[K], valuesAdapter ObjectAdapter[V], prng *Prng) error {
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
