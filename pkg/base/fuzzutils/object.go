package fuzzutils

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type Object any
type ObjectUnderlyer = Underlyer

type ObjectAdapter[O Object] AbstractAdapter[ObjectUnderlyer, O]

type ObjectGenerator[O Object] interface {
	Generate() O
	GenerateNonZero() O

	Adapter() ObjectAdapter[O]
	Clone() ObjectGenerator[O]
	Generator[O]
}

var _ ObjectGenerator[any] = (*objectGenerator[any])(nil)

type objectGenerator[O Object] struct {
	generator[ObjectUnderlyer, O]
}

func (o objectGenerator[O]) Generate() O {
	x := o.Prng().Underlyer(false)
	return o.adapter.Wrap(x)
}
func (o objectGenerator[O]) GenerateNonZero() O {
	x := o.Prng().Underlyer(true)
	return o.adapter.Wrap(x)
}
func (o objectGenerator[O]) Adapter() ObjectAdapter[O] {
	return o.adapter
}
func (o objectGenerator[O]) Clone() ObjectGenerator[O] {
	return objectGenerator[O]{
		generator[ObjectUnderlyer, O]{
			prng:    o.Prng().Clone(),
			adapter: o.adapter,
		},
	}
}

func NewObjectGenerator[O Object](adapter ObjectAdapter[O], prng *Prng) (ObjectGenerator[O], error) {
	if err := validateNewObjectGenerator(adapter, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}
	return &objectGenerator[O]{
		generator[ObjectUnderlyer, O]{
			prng:    *prng,
			adapter: adapter,
		},
	}, nil
}

func validateNewObjectGenerator[O Object](adapter ObjectAdapter[O], prng *Prng) error {
	if adapter == nil {
		return errs.NewIsNil("adapter")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}
