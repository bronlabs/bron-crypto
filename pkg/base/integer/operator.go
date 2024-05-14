package integer

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
)

const (
	Addition       algebra.Operator = "Integer_Addition"
	Multiplication algebra.Operator = "Integer_Multiplication"
)

func NewAdditionOperator[T any](arithmetic Arithmetic[T]) algebra.Addition[T] {
	return operator.NewAdditionOperator(Addition, arithmetic.Add)
}

func NewMultiplicationOperator[T any](arithmetic Arithmetic[T]) algebra.Multiplication[T] {
	return operator.NewMultiplicationOperator(Multiplication, arithmetic.Mul)
}
