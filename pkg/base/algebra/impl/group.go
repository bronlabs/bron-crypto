package impl

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferith_utils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

type GroupElement[G algebra.Group[G, E], E algebra.GroupElement[G, E]] struct {
	algebra.GroupElement[G, E]
}

func (e *GroupElement[G, E]) IsInverse(of GroupElement[G, E], under algebra.BinaryOperator[E]) (bool, error) {
	if !e.Structure().IsDefinedUnder(under) {
		return false, errs.NewArgument("invalid operator")
	}
	image, err := under.Map(e.Unwrap(), of.Unwrap())
	if err != nil {
		return false, errs.WrapFailed(err, "could not apply the given operator")
	}
	return image.IsIdentity(under) //nolint:wrapcheck // forwarding errors
}

func (e *GroupElement[G, E]) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[E]) (bool, error) {
	cursor := new(saferith.Nat).SetBytes(order.Bytes())
	identity, err := e.Structure().Identity(under)
	if err != nil {
		return false, errs.WrapFailed(err, "could not derive identity element")
	}
	result := identity.Clone()
	for cursor.EqZero() == 0 {
		result, err = under.Map(result, identity)
		if err != nil {
			return false, errs.WrapFailed(err, "could not apply operator")
		}
		cursor = saferith_utils.NatDec(cursor)
	}

	resultIsIdentity, err := result.IsIdentity(under)
	if err != nil {
		return false, errs.WrapFailed(err, "could not check if result is identity")
	}
	return resultIsIdentity, nil
}

type AdditiveGroup[G algebra.AdditiveGroup[G, E], E algebra.AdditiveGroupElement[G, E]] struct {
	algebra.AdditiveGroup[G, E]
}

func (*AdditiveGroup[G, E]) Sub(x algebra.AdditiveGroupElement[G, E], ys ...algebra.AdditiveGroupElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Sub(y)
	}
	return sum.Unwrap()
}

func (*AdditiveGroup[G, E]) Add(x algebra.AdditiveGroupoidElement[G, E], ys ...algebra.AdditiveGroupoidElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

type AdditiveGroupElement[G algebra.AdditiveGroup[G, E], E algebra.AdditiveGroupElement[G, E]] struct {
	algebra.AdditiveGroupElement[G, E]
}

func (e *AdditiveGroupElement[G, E]) IsAdditiveInverse(of algebra.AdditiveGroupElement[G, E]) bool {
	return e.Unwrap().Add(of).IsAdditiveIdentity()
}

func (e *AdditiveGroupElement[G, E]) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	cursor := new(saferith.Nat).SetBytes(order.Bytes())
	result := e.Clone()
	for cursor.EqZero() == 0 {
		result = result.Add(result)
		cursor = saferith_utils.NatDec(cursor)
	}

	return result.IsAdditiveIdentity()
}

func (e *AdditiveGroupElement[G, E]) Neg() E {
	return e.Unwrap().AdditiveInverse()
}

func (e *AdditiveGroupElement[G, E]) ApplySub(x algebra.AdditiveGroupElement[G, E], n *saferith.Nat) E {
	cursor := new(saferith.Nat).SetUint64(1)
	res := e.Clone()
	for cursor.Eq(n) != 1 {
		res = res.Sub(x)
		cursor = saferith_utils.NatInc(cursor)
	}
	return res
}

type MultiplicativeGroup[G algebra.MultiplicativeGroup[G, E], E algebra.MultiplicativeGroupElement[G, E]] struct {
	algebra.MultiplicativeGroup[G, E]
}

func (*MultiplicativeGroup[G, E]) Div(x algebra.MultiplicativeGroupElement[G, E], ys ...algebra.MultiplicativeGroupElement[G, E]) (E, error) {
	var err error
	res := x
	for _, y := range ys {
		res, err = x.Div(y)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not divide x by y")
		}
	}
	return res.Unwrap(), nil
}

type MultiplicativeGroupElement[G algebra.MultiplicativeGroup[G, E], E algebra.MultiplicativeGroupElement[G, E]] struct {
	algebra.MultiplicativeGroupElement[G, E]
}

func (e *MultiplicativeGroupElement[G, E]) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[G, E]) bool {
	return e.Unwrap().Mul(of).IsMultiplicativeIdentity()
}

func (e *MultiplicativeGroupElement[G, E]) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	cursor := new(saferith.Nat).SetBytes(order.Bytes())
	result := e.Clone()
	for cursor.EqZero() == 0 {
		result = result.Mul(result)
		cursor = saferith_utils.NatDec(cursor)
	}

	return result.IsMultiplicativeIdentity()
}

func (e *MultiplicativeGroupElement[G, E]) ApplyDiv(x algebra.MultiplicativeGroupElement[G, E], n *saferith.Nat) (E, error) {
	cursor := new(saferith.Nat).SetUint64(1)
	var err error
	res := e.Clone()
	for cursor.Eq(n) != 1 {
		res, err = res.Div(x)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not divide by x")
		}
		cursor = saferith_utils.NatInc(cursor)
	}
	return res, nil
}

type CyclicGroup[G algebra.CyclicGroup[G, E], E algebra.CyclicGroupElement[G, E]] struct {
	algebra.CyclicGroup[G, E]
}

func (g *CyclicGroup[G, E]) DLog(base, x algebra.CyclicGroupElement[G, E], under algebra.BinaryOperator[E]) (*saferith.Nat, error) {
	if !g.Unwrap().IsDefinedUnder(under) {
		return nil, errs.NewArgument("invalid operator")
	}
	order := g.Unwrap().Order().Nat()
	exponent := new(saferith.Nat).SetUint64(1)
	for exponent.Eq(order) != 1 {
		bexp, err := base.ApplyOp(under, base, exponent)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not raise b to current exponent")
		}
		if x.Equal(bexp) {
			return exponent, nil
		}
		exponent = saferith_utils.NatInc(exponent)
	}
	bexp, err := base.ApplyOp(under, base, exponent)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not raise b to current exponent")
	}
	if !x.Equal(bexp) {
		return nil, errs.WrapFailed(err, "could not find dlog")
	}
	return exponent, nil
}
