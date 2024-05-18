package operator

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

var _ algebra.ExclusiveDisjunction[any] = (*ExclusiveDisjunction[any])(nil)

type ExclusiveDisjunction[E algebra.Element] struct {
	BiEndoFunction[E]
	BinaryOperator[E]
	RightAssociativeBiEndoFunction[E]
}

func (a *ExclusiveDisjunction[E]) Xor(x, y E) E {
	out, err := a.Map(x, y)
	if err != nil {
		panic(err)
	}
	return out
}

func NewExclusiveDisjunctionOperator[E algebra.Element](name algebra.Operator, f func(x, y E) (E, error)) algebra.ExclusiveDisjunction[E] {
	out := &ExclusiveDisjunction[E]{}
	out.Name_ = name
	out.Map_ = f
	return out
}
