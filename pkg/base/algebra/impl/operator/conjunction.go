package operator

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

var _ algebra.Conjunction[any] = (*Conjunction[any])(nil)

type Conjunction[E algebra.Element] struct {
	BiEndoFunction[E]
	BinaryOperator[E]
	RightAssociativeBiEndoFunction[E]
}

func (a *Conjunction[E]) And(x, y E) E {
	out, err := a.Map(x, y)
	if err != nil {
		panic(err)
	}
	return out
}

func NewConjunctionOperator[E algebra.Element](name algebra.Operator, f func(x, y E) (E, error)) algebra.Conjunction[E] {
	out := &Conjunction[E]{}
	out.Name_ = name
	out.Map_ = f
	return out
}
