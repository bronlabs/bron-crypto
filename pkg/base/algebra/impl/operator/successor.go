package operator

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

var _ algebra.Successor[any] = (*Successor[any])(nil)

type Successor[E algebra.Element] struct {
	UnaryOperator[E]
}

func (s *Successor[E]) Next(x E) E {
	out, err := s.Map_(x)
	if err != nil {
		panic(err)
	}
	return out
}

func NewSuccessor[E algebra.Element](name algebra.Operator, structure algebra.Set[E], f func(x E) (E, error)) algebra.Successor[E] {
	out := &Successor[E]{}
	out.Name_ = name
	out.Set_ = structure
	out.Map_ = f
	return out
}
