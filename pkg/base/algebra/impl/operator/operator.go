package operator

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/itertools"
)

type EndoFunction[E algebra.Element] struct {
	Map_ func(x E) (E, error)
	Set_ algebra.Set[E]
}

func (op *EndoFunction[E]) Arity() uint {
	return 1
}

func (op *EndoFunction[E]) Map(x E) (E, error) {
	return op.Map_(x)
}

func (op *EndoFunction[E]) Dom() algebra.Set[E] {
	return op.Set_
}

func (op *EndoFunction[E]) Cod() algebra.Set[E] {
	return op.Set_
}

type UnaryOperator[E algebra.Element] struct {
	EndoFunction[E]
	Name_ algebra.Operator
}

func (op *UnaryOperator[E]) Name() algebra.Operator {
	return op.Name_
}

type BiEndoFunction[E algebra.Element] struct {
	Map_ func(x, y E) (E, error)
}

func (op *BiEndoFunction[E]) Arity() uint {
	return 2
}

func (op *BiEndoFunction[E]) Map(x, y E) (E, error) {
	return op.Map_(x, y)
}

type RightAssociativeBiEndoFunction[E algebra.Element] struct {
	BiEndoFunction[E]
}

func (op *RightAssociativeBiEndoFunction[E]) RFold(xs ...E) (E, error) {
	if len(xs) < 1 {
		return *new(E), errs.NewLength("need at least one input")
	}
	res, err := itertools.FoldRightOrError(op.Map, xs[len(xs)-1], xs...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not right fold")
	}
	return res, nil
}

type LeftAssociativeBiEndoFunction[E algebra.Element] struct {
	BiEndoFunction[E]
}

func (op *LeftAssociativeBiEndoFunction[E]) LFold(xs ...E) (E, error) {
	if len(xs) < 1 {
		return *new(E), errs.NewLength("need at least one input")
	}
	res, err := itertools.FoldOrError(op.Map, xs[0], xs...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not right fold")
	}
	return res, nil
}

type BinaryOperator[E algebra.Element] struct {
	BiEndoFunction[E]
	LeftAssociativeBiEndoFunction[E]
	Name_ algebra.Operator
}

func (op *BinaryOperator[E]) Name() algebra.Operator {
	return op.Name_
}
