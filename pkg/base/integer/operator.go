package integer

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
)

const (
	Successor      algebra.Operator = "Integer_Successor"
	Addition       algebra.Operator = "Integer_Addition"
	Multiplication algebra.Operator = "Integer_Multiplication"
)

func NewAdditionOperator[T any](arithmetic Arithmetic[T]) algebra.Addition[T] {
	return operator.NewAdditionOperator(Addition, arithmetic.Add)
}

func NewMultiplicationOperator[T any](arithmetic Arithmetic[T]) algebra.Multiplication[T] {
	return operator.NewMultiplicationOperator(Multiplication, arithmetic.Mul)
}

func succ[T any](arithmetic Arithmetic[T]) func(x T) (T, error) {
	return func(x T) (T, error) {
		return arithmetic.Add(x, arithmetic.One())
	}
}

func NewSuccessorOperator[E algebra.Element](arithmetic Arithmetic[E], constructor func() algebra.Set[E]) algebra.Successor[E] {
	return operator.NewSuccessor[E](Successor, constructor(), succ(arithmetic))
}
