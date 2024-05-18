package operator

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

var _ algebra.AlternativeDenial[any] = (*AlternativeDenial[any])(nil)

type AlternativeDenial[E algebra.Element] struct {
	BiEndoFunction[E]
	BinaryOperator[E]
	RightAssociativeBiEndoFunction[E]
}

func (a *AlternativeDenial[E]) Nand(x, y E) E {
	out, err := a.Map(x, y)
	if err != nil {
		panic(err)
	}
	return out
}

func NewAlternativeDenialOperator[E algebra.Element](name algebra.Operator, f func(x, y E) (E, error)) algebra.AlternativeDenial[E] {
	out := &AlternativeDenial[E]{}
	out.Name_ = name
	out.Map_ = f
	return out
}
