package operator

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

var _ algebra.Multiplication[any] = (*Multiplication[any])(nil)

type Multiplication[E algebra.Element] struct {
	BiEndoFunction[E]
	BinaryOperator[E]
	RightAssociativeBiEndoFunction[E]
}

func (a *Multiplication[E]) Multiply(x, y E) E {
	out, err := a.Map(x, y)
	if err != nil {
		panic(err)
	}
	return out
}

func NewMultiplicationOperator[E algebra.Element](name algebra.Operator, f func(x, y E) (E, error)) algebra.Multiplication[E] {
	out := &Multiplication[E]{}
	out.Name_ = name
	out.Map_ = f
	return out
}
