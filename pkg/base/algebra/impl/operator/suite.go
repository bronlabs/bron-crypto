package operator

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type OperatorSuite[E algebra.Element] struct {
	binOp     map[algebra.Operator]algebra.BinaryOperator[E]
	unOp      map[algebra.Operator]algebra.UnaryOperator[E]
	primary   algebra.Operator
	secondary algebra.Operator
}

func (ops *OperatorSuite[E]) GetUnaryOperator(name algebra.Operator) (algebra.UnaryOperator[E], bool) {
	out, exists := ops.unOp[name]
	return out, exists
}

func (ops *OperatorSuite[E]) GetOperator(name algebra.Operator) (algebra.BinaryOperator[E], bool) {
	out, exists := ops.binOp[name]
	return out, exists
}

type Builder[E algebra.Element] struct {
	v OperatorSuite[E]
}

func (b *Builder[E]) WithUnaryOperator(op algebra.UnaryOperator[E]) *Builder[E] {
	b.v.unOp[op.Name()] = op
	return b
}

func (b *Builder[E]) WithBinaryOperator(op algebra.BinaryOperator[E]) *Builder[E] {
	b.v.binOp[op.Name()] = op
	return b
}

func (b *Builder[E]) WithPrimary(op algebra.BinaryOperator[E]) *Builder[E] {
	b.v.primary = op.Name()
	b.WithBinaryOperator(op)
	return b
}

func (b *Builder[E]) WithSecondary(op algebra.BinaryOperator[E]) *Builder[E] {
	b.v.secondary = op.Name()
	b.WithBinaryOperator(op)
	return b
}

func (b *Builder[E]) Build() OperatorSuite[E] {
	return b.v
}

func NewOperatorSuiteBuilder[E algebra.Element]() *Builder[E] {
	return &Builder[E]{
		v: OperatorSuite[E]{
			binOp: make(map[algebra.Operator]algebra.BinaryOperator[E]),
			unOp:  make(map[algebra.Operator]algebra.UnaryOperator[E]),
		},
	}
}
