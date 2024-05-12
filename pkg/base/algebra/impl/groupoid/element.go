package groupoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferith_utils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/cronokirby/saferith"
)

type GroupoidElement[G algebra.Groupoid[G, E], E algebra.GroupoidElement[G, E]] struct {
	algebra.GroupoidElement[G, E]
}

func (e *GroupoidElement[G, E]) Order(under algebra.Operator) (*saferith.Nat, error) {
	op, defined := e.Structure().GetOperator(under)
	if !defined {
		return nil, errs.NewType("structure not defined under %s", under)
	}
	if e.Structure().Order().Nat().EqZero() == 1 {
		return new(saferith.Nat).SetUint64(1), nil
	}
	var err error
	current := e.Clone()
	order := new(saferith.Nat).SetUint64(1)
	for {
		current, err = op.Map(current.Unwrap(), e.Unwrap())
		if err != nil {
			return nil, errs.WrapFailed(err, "could not apply operator")
		}
		if current.Equal(e.Unwrap()) {
			break
		}
	}
	return order, nil

}

func (e *GroupoidElement[G, E]) Operate(under algebra.Operator, rhs algebra.GroupoidElement[G, E]) (E, error) {
	op, exists := e.Structure().GetOperator(under)
	if !exists {
		return *new(E), errs.NewMissing("structure is not defined under %s", under)
	}
	out, err := op.Map(e.Unwrap(), rhs.Unwrap())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not apply the operator %s", under)
	}
	return out, nil
}

func (e *GroupoidElement[G, E]) Apply(over algebra.Operator, x algebra.GroupoidElement[G, E], count *saferith.Nat) (E, error) {
	op, defined := e.Structure().GetOperator(over)
	if !defined {
		return *new(E), errs.NewType("structure not defined under %s", over)
	}

	var err error
	cursor := new(saferith.Nat).SetUint64(1)
	res := e.Clone()
	for cursor.Eq(count) != 1 {
		res, err = op.Map(res.Unwrap(), x.Unwrap())
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not apply operator")
		}
		cursor = saferith_utils.NatInc(cursor)
	}
	return res, nil
}

func (e *GroupoidElement[G, E]) CanGenerateAllElements(with algebra.Operator) bool {
	order, err := e.Order(with)
	if err != nil {
		return false
	}
	return e.Structure().Order().Nat().Eq(order) == 1
}

type AdditiveGroupoidElement[G algebra.AdditiveGroupoid[G, E], E algebra.AdditiveGroupoidElement[G, E]] struct {
	algebra.AdditiveGroupoidElement[G, E]
}

func (e *AdditiveGroupoidElement[G, E]) ApplyAdd(x algebra.AdditiveGroupoidElement[G, E], n *saferith.Nat) E {
	out, err := e.Apply(e.Structure().Addition().Name(), x, n)
	if err != nil {
		panic(errs.WrapFailed(err, "could not apply addition"))
	}
	return out
}

func (e *AdditiveGroupoidElement[_, E]) Double() E {
	return e.Add(e)
}

func (e *AdditiveGroupoidElement[_, E]) Triple() E {
	return e.Double().Add(e)
}

type MultiplicativeGroupoidElement[G algebra.MultiplicativeGroupoid[G, E], E algebra.MultiplicativeGroupoidElement[G, E]] struct {
	algebra.MultiplicativeGroupoidElement[G, E]
}

func (e *MultiplicativeGroupoidElement[G, E]) ApplyMul(x algebra.MultiplicativeGroupoidElement[G, E], n *saferith.Nat) E {
	out, err := e.Apply(e.Structure().Multiplication().Name(), x, n)
	if err != nil {
		panic(errs.WrapFailed(err, "could not apply addition"))
	}
	return out
}

func (e *MultiplicativeGroupoidElement[_, E]) Square() E {
	return e.Mul(e)
}

func (e *MultiplicativeGroupoidElement[_, E]) Cube() E {
	return e.Square().Mul(e)
}

func (e *MultiplicativeGroupoidElement[_, E]) Exp(exponent *saferith.Nat) E {
	return e.ApplyMul(e.Unwrap(), exponent)
}

type CyclicGroupoidElement[G algebra.CyclicGroupoid[G, E], E algebra.CyclicGroupoidElement[G, E]] struct {
	algebra.CyclicGroupoidElement[G, E]
}

func (e *CyclicGroupoidElement[G, E]) Order(under algebra.BinaryOperator[E]) (*saferith.Modulus, error) {
	if _, exists := e.Structure().GetOperator(under.Name()); !exists {
		return nil, errs.NewArgument("not defined under given operator")
	}
	return e.Structure().Order(), nil
}

func (e *CyclicGroupoidElement[G, E]) CanGenerateAllElements(with algebra.BinaryOperator[E]) bool {
	_, defined := e.Structure().GetOperator(with.Name())
	return defined
}

func (e *CyclicGroupoidElement[G, E]) IsDesignatedGenerator() bool {
	return e.IsBasePoint()
}
