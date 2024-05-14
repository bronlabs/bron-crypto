package operator

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

var _ algebra.Addition[any] = (*Addition[any])(nil)

type Addition[E algebra.Element] struct {
	BiEndoFunction[E]
	BinaryOperator[E]
	RightAssociativeBiEndoFunction[E]
}

func (a *Addition[E]) Add(x, y E) E {
	out, err := a.Map(x, y)
	if err != nil {
		panic(err)
	}
	return out
}

func NewAdditionOperator[E algebra.Element](name algebra.Operator, f func(x, y E) (E, error)) algebra.Addition[E] {
	out := &Addition[E]{}
	out.Name_ = name
	out.Map_ = f
	return out
}
