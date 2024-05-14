package operator

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferith_utils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/cronokirby/saferith"
)

var _ algebra.DiscreteExponentiation[any] = (*DiscreteExponentiation[any])(nil)

type DiscreteExponentiation[E algebra.Element] struct {
	BiEndoFunction[E]
	BinaryOperator[E]
	RightAssociativeBiEndoFunction[E]
	One E
}

func (a *DiscreteExponentiation[E]) mul(x, y E) (E, error) {
	return a.Map_(x, y)
}

func (a *DiscreteExponentiation[E]) Exp(x E, exponent *saferith.Nat) E {
	if exponent == nil {
		panic(errs.NewIsNil("exponent"))
	}
	if exponent.EqZero() == 1 {
		return a.One
	}
	if exponent.Eq(saferith_utils.NatOne) == 1 {
		return x
	}
	res, err := a.mul(x, x)
	if err != nil {
		panic(errs.WrapFailed(err, "could not mul"))
	}
	current := new(saferith.Nat).SetUint64(3)
	for current.Eq(exponent) != 1 {
		res, err = a.mul(x, x)
		if err != nil {
			panic(errs.WrapFailed(err, "could not mul"))
		}
		current = saferith_utils.NatInc(current)
	}
	return res
}

func NewDiscreteExponentiationOperator[E algebra.Element](name algebra.Operator, one E, mul func(x, y E) (E, error)) algebra.DiscreteExponentiation[E] {
	out := &DiscreteExponentiation[E]{}
	out.Name_ = name
	out.Map_ = mul
	out.One = one
	return out
}
