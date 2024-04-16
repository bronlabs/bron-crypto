package impl

import (
	"reflect"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/cronokirby/saferith"
)

type Groupoid[G algebra.Groupoid[G, E], E algebra.GroupoidElement[G, E]] struct {
	algebra.Groupoid[G, E]
}

func (g *Groupoid[G, E]) Order() *saferith.Modulus {
	return g.Cardinality()
}

func (g *Groupoid[G, E]) IsDefinedUnder(operator algebra.BinaryOperator[E]) bool {
	for _, definedOp := range g.Operators() {
		if reflect.TypeOf(definedOp) == reflect.TypeOf(operator) {
			return true
		}
	}
	return false
}

func (g *Groupoid[G, E]) Op(operator algebra.BinaryOperator[E], x algebra.GroupoidElement[G, E], ys ...algebra.GroupoidElement[G, E]) (E, error) {
	if !g.IsDefinedUnder(operator) {
		return *new(E), errs.NewType("groupoid is not defined under given operator")
	}
	var err error
	result := x.Clone()
	for _, y := range ys {
		result, err = operator.Map(result, y.Unwrap())
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not apply operator")
		}
	}
	return result, nil
}

type GroupoidElement[G algebra.Groupoid[G, E], E algebra.GroupoidElement[G, E]] struct {
	algebra.GroupoidElement[G, E]
}

func (e *GroupoidElement[G, E]) Order(operator algebra.BinaryOperator[E]) (*saferith.Modulus, error) {
	if !e.Structure().IsDefinedUnder(operator) {
		return nil, errs.NewArgument("not defined under given operator")
	}
	x := e.Clone()
	order := new(saferith.Nat).SetUint64(1)
	for {
		x, err := operator.Map(x, e.Unwrap())
		if err != nil {
			return nil, errs.WrapFailed(err, "could not apply the operator")
		}
		utils.IncrementNat(order)
		if e.Equal(x) {
			return saferith.ModulusFromNat(order), nil
		}
	}
}

func (e *GroupoidElement[G, E]) ApplyOp(operator algebra.BinaryOperator[E], x GroupoidElement[G, E], n *saferith.Nat) (E, error) {
	if !e.Structure().IsDefinedUnder(operator) {
		return *new(E), errs.NewType("groupoid is not defined under given operator")
	}
	var err error
	result := e.Clone()
	cursor := new(saferith.Nat).SetUint64(1)
	for cursor.Eq(n) != 1 {
		result, err = operator.Map(result, x.Unwrap())
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not apply operator")
		}
		cursor = utils.IncrementNat(cursor)
	}
	return result, nil
}

type AdditiveGroupoid[G algebra.AdditiveGroupoid[G, E], E algebra.AdditiveGroupoidElement[G, E]] struct {
	algebra.AdditiveGroupoid[G, E]
}

func (g *AdditiveGroupoid[G, E]) Add(x algebra.AdditiveGroupoidElement[G, E], ys ...algebra.AdditiveGroupoidElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()

}

type AdditiveGroupoidElement[G algebra.AdditiveGroupoid[G, E], E algebra.AdditiveGroupoidElement[G, E]] struct {
	algebra.AdditiveGroupoidElement[G, E]
}

func (e *AdditiveGroupoidElement[G, E]) ApplyAdd(x algebra.AdditiveGroupoidElement[G, E], n *saferith.Nat) E {
	cursor := new(saferith.Nat).SetUint64(1)
	sum := e.Clone()
	for cursor.Eq(n) != 1 {
		sum = sum.Add(x)
		cursor = utils.IncrementNat(cursor)
	}
	return sum
}

func (e *AdditiveGroupoidElement[_, E]) Double() E {
	return e.Add(e)
}

func (e *AdditiveGroupoidElement[_, E]) Triple() E {
	return e.Double().Add(e)
}

type MultiplicativeGroupoid[G algebra.MultiplicativeGroupoid[G, E], E algebra.MultiplicativeGroupoidElement[G, E]] struct {
	algebra.MultiplicativeGroupoid[G, E]
}

func (g *MultiplicativeGroupoid[G, E]) Mul(x algebra.MultiplicativeGroupoidElement[G, E], ys ...algebra.MultiplicativeGroupoidElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Mul(y)
	}
	return sum.Unwrap()

}

func (g *MultiplicativeGroupoid[G, E]) Exp(base algebra.MultiplicativeGroupoidElement[G, E], exponent *saferith.Nat) E {
	return base.Exp(exponent)
}

func (g *MultiplicativeGroupoid[G, E]) SimExp(bases []algebra.MultiplicativeGroupoidElement[G, E], exponents []*saferith.Nat) (E, error) {
	if len(bases) != len(exponents) {
		return *new(E), errs.NewSize("#bases != #exponents")
	}
	prod := g.Exp(bases[0], exponents[0])
	for i, bi := range bases[1:] {
		prod = prod.Mul(g.Exp(bi, exponents[i]))
	}
	return prod, nil
}

func (g *MultiplicativeGroupoid[G, E]) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[G, E], exponent *saferith.Nat) E {
	prod := g.Exp(bases[0], exponent)
	for _, bi := range bases[1:] {
		prod = prod.Mul(g.Exp(bi, exponent))
	}
	return prod
}

func (g *MultiplicativeGroupoid[G, E]) MultiExponentExp(base algebra.MultiplicativeGroupoidElement[G, E], exponents []*saferith.Nat) E {
	prod := g.Exp(base, exponents[0])
	for _, exp := range exponents[1:] {
		prod = prod.Mul(g.Exp(base, exp))
	}
	return prod
}

type MultiplicativeGroupoidElement[G algebra.MultiplicativeGroupoid[G, E], E algebra.MultiplicativeGroupoidElement[G, E]] struct {
	algebra.MultiplicativeGroupoidElement[G, E]
}

func (e *MultiplicativeGroupoidElement[G, E]) ApplyMul(x algebra.MultiplicativeGroupoidElement[G, E], n *saferith.Nat) E {
	cursor := new(saferith.Nat).SetUint64(1)
	sum := e.Clone()
	for cursor.Eq(n) != 1 {
		sum = sum.Mul(x)
		cursor = utils.IncrementNat(cursor)
	}
	return sum
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

type CyclicGroupoid[G algebra.CyclicGroupoid[G, E], E algebra.CyclicGroupoidElement[G, E]] struct {
	algebra.CyclicGroupoid[G, E]
}

func (g *CyclicGroupoid[G, E]) Generator() E {
	return g.BasePoint()
}

type CyclicGroupoidElement[G algebra.CyclicGroupoid[G, E], E algebra.CyclicGroupoidElement[G, E]] struct {
	algebra.CyclicGroupoidElement[G, E]
}

func (e *CyclicGroupoidElement[G, E]) Order(operator algebra.BinaryOperator[E]) (*saferith.Modulus, error) {
	if !e.Structure().IsDefinedUnder(operator) {
		return nil, errs.NewArgument("not defined under given operator")
	}
	return e.Structure().Order(), nil
}
