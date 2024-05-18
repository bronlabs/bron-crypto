package operator

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

var _ algebra.Negation[any] = (*Negation[any])(nil)

type Negation[E algebra.Element] struct {
	UnaryOperator[E]
}

func (s *Negation[E]) Not(x E) E {
	out, err := s.Map_(x)
	if err != nil {
		panic(err)
	}
	return out
}

func NewNegation[E algebra.Element](name algebra.Operator, structure algebra.Set[E], f func(x E) (E, error)) algebra.Negation[E] {
	out := &Negation[E]{}
	out.Name_ = name
	out.Set_ = structure
	out.Map_ = f
	return out
}
