package operator

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type OperatorSuite[E algebra.Element] struct {
	m        map[algebra.Operator]algebra.BinaryOperator[E]
	addition algebra.Operator
	mult     algebra.Operator
}

func (ops *OperatorSuite[E]) Operator(name algebra.Operator) (algebra.BinaryOperator[E], bool) {
	out, exists := ops.m[name]
	return out, exists
}

type Builder[E algebra.Element] struct {
	v OperatorSuite[E]
}

func (b *Builder[E]) WithAddition(op algebra.BinaryOperator[E]) *Builder[E] {
	b.v.addition = op.Name()
	b.v.m[b.v.addition] = op
	return b
}

func (b *Builder[E]) WithMultiplication(op algebra.BinaryOperator[E]) *Builder[E] {
	b.v.mult = op.Name()
	b.v.m[b.v.mult] = op
	return b
}

func (b *Builder[E]) Build() (OperatorSuite[E], error) {
	out := b.v
	if out.addition != "" {
		if _, ok := out.m[out.addition].(algebra.Addition[E]); !ok {
			return *new(OperatorSuite[E]), errs.NewType("provided addition operator is invalid")
		}
	}
	if out.mult != "" {
		if _, ok := out.m[out.mult].(algebra.Multiplication[E]); !ok {
			return *new(OperatorSuite[E]), errs.NewType("provided multiplication operator is invalid")
		}
	}
	return out, nil
}

func NewOperatorSuiteBuilder[E algebra.Element]() *Builder[E] {
	return &Builder[E]{
		v: OperatorSuite[E]{
			m: make(map[algebra.Operator]algebra.BinaryOperator[E]),
		},
	}
}
