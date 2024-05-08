package testutils2

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
)

type Object any
type ObjectUnderlyer = UnderlyerType

type ObjectAdapter[O Object] AbstractAdapter[ObjectUnderlyer, O]

type ObjectGenerator[O Object] interface {
	Generate() O
	GenerateNonZero() O
	Generator[O]
}

var _ ObjectGenerator[any] = (*ObjectGenerationSuite[any])(nil)

type ObjectGenerationSuite[O Object] struct {
	GeneratorTrait[ObjectUnderlyer, O]
}

func (o *ObjectGenerationSuite[O]) Generate() O {
	x, err := RandomUnderlyer[ObjectUnderlyer](o.prng, false)
	if err != nil {
		panic(errs.WrapFailed(err, "could not generate random underlyer"))
	}
	return o.adapter.Wrap(x)
}
func (o *ObjectGenerationSuite[O]) GenerateNonZero() O {
	x, err := RandomUnderlyer[ObjectUnderlyer](o.prng, true)
	if err != nil {
		panic(errs.WrapFailed(err, "could not generate non zero random underlyer"))
	}
	return o.adapter.Wrap(x)
}

func NewObjectGenerationSuite[O Object](adapter ObjectAdapter[O], prng csprng.Seedable) (*ObjectGenerationSuite[O], error) {
	if err := validateNewObjectGenerationSuite(adapter, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}
	return &ObjectGenerationSuite[O]{
		GeneratorTrait[ObjectUnderlyer, O]{
			prng:    prng,
			adapter: adapter,
		},
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
