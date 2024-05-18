package operator

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

var _ algebra.Disjunction[any] = (*Disjunction[any])(nil)

type Disjunction[E algebra.Element] struct {
	BiEndoFunction[E]
	BinaryOperator[E]
	RightAssociativeBiEndoFunction[E]
}

func (a *Disjunction[E]) Or(x, y E) E {
	out, err := a.Map(x, y)
	if err != nil {
		panic(err)
	}
	return out
}

func NewDisjunctionOperator[E algebra.Element](name algebra.Operator, f func(x, y E) (E, error)) algebra.Disjunction[E] {
	out := &Disjunction[E]{}
	out.Name_ = name
	out.Map_ = f
	return out
}
