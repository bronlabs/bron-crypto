package testutils2

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
)

type Object any

type AbstractObjectAdapter[T any, O Object] interface {
	Wrap(T) O
	Unwrap(O) T
	Zero() O
	IsZero(O) bool
}

type ObjectAdapter[O Object] AbstractObjectAdapter[UnderlyingGenerator, O]

type ObjectGenerator[O Object] interface {
	Generate() O
	GenerateNonZero() O
	Generator[O]
}

var _ ObjectGenerator[any] = (*ObjectGenerationSuite[any])(nil)

type ObjectGenerationSuite[O Object] struct {
	adapter ObjectAdapter[O]
	prng    csprng.Seedable
}

func (o *ObjectGenerationSuite[O]) Generate() O {
	x, err := RandomUnderlyer(o.prng, false)
	if err != nil {
		panic(errs.WrapFailed(err, "could not generate random underlyer"))
	}
	return o.adapter.Wrap(x)
}
func (o *ObjectGenerationSuite[O]) GenerateNonZero() O {
	x, err := RandomUnderlyer(o.prng, true)
	if err != nil {
		panic(errs.WrapFailed(err, "could not generate non zero random underlyer"))
	}
	return o.adapter.Wrap(x)
}
func (o *ObjectGenerationSuite[O]) Empty() O {
	return o.adapter.Zero()
}
func (o *ObjectGenerationSuite[O]) Prng() csprng.Seedable {
	return o.prng
}

func NewObjectGenerationSuite[O Object](adapter ObjectAdapter[O], prng csprng.Seedable) (*ObjectGenerationSuite[O], error) {
	if err := validateNewObjectGenerationSuite(adapter, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}
	return &ObjectGenerationSuite[O]{
		adapter: adapter,
		prng:    prng,
	}, nil
}

func validateNewObjectGenerationSuite[O Object](adapter ObjectAdapter[O], prng csprng.Seedable) error {
	if adapter == nil {
		return errs.NewIsNil("adapter")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}
