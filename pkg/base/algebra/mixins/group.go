package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/cronokirby/saferith"
)

type Group[G algebra.Group[G, E], E algebra.GroupElement[G, E]] struct {
	algebra.Group[G, E]
	Monoid[G, E]
}

type GroupElement[G algebra.Group[G, E], E algebra.GroupElement[G, E]] struct {
	algebra.GroupElement[G, E]
	Monoid[G, E]
}

func (e *GroupElement[G, E]) IsInverse(of GroupElement[G, E], under algebra.BinaryOperator[E]) (bool, error) {
	if !e.Structure().IsDefinedUnder(under) {
		return false, errs.NewArgument("invalid operator")
	}
	image, err := under.Map(e.Unwrap(), of.Unwrap())
	if err != nil {
		return false, errs.WrapFailed(err, "could not apply the given operator")
	}
	return image.IsIdentity(under)
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
		cursor = utils.DecrementNat(cursor)
	}

	resultIsIdentity, err := result.IsIdentity(under)
	if err != nil {
		return false, errs.WrapFailed(err, "could not check if result is identity")
	}
	return resultIsIdentity, nil
}

type SubGroup[G algebra.SubGroup[G, E], E algebra.SubGroupElement[G, E]] struct {
	algebra.SubGroup[G, E]
	Group[G, E]
}

type SubGroupElement[G algebra.SubGroup[G, E], E algebra.SubGroupElement[G, E]] struct {
	algebra.SubGroupElement[G, E]
	GroupElement[G, E]
}

type AdditiveGroup[G algebra.AdditiveGroup[G, E], E algebra.AdditiveGroupElement[G, E]] struct {
	algebra.AdditiveGroup[G, E]
	Group[G, E]
	AdditiveMonoid[G, E]
}

func (g *AdditiveGroup[G, E]) Sub(x algebra.AdditiveGroupElement[G, E], ys ...algebra.AdditiveGroupElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Sub(y)
	}
	return sum.Unwrap()

}

func (g *AdditiveGroup[G, E]) Add(x algebra.AdditiveGroupoidElement[G, E], ys ...algebra.AdditiveGroupoidElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()

}

type AdditiveGroupElement[G algebra.AdditiveGroup[G, E], E algebra.AdditiveGroupElement[G, E]] struct {
	algebra.AdditiveGroupElement[G, E]
	GroupElement[G, E]
	AdditiveMonoidElement[G, E]
}

func (e *AdditiveGroupElement[G, E]) IsAdditiveInverse(of algebra.AdditiveGroupElement[G, E]) bool {
	return e.Unwrap().Add(of).IsAdditiveIdentity()
}

func (e *AdditiveGroupElement[G, E]) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	cursor := new(saferith.Nat).SetBytes(order.Bytes())
	result := e.Clone()
	for cursor.EqZero() == 0 {
		result = result.Add(e.Structure().AdditiveIdentity())
		cursor = utils.DecrementNat(cursor)
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
		cursor = utils.IncrementNat(cursor)
	}
	return res
}

type MultiplicativeGroup[G algebra.MultiplicativeGroup[G, E], E algebra.MultiplicativeGroupElement[G, E]] struct {
	algebra.MultiplicativeGroup[G, E]
	Group[G, E]
	MultiplicativeMonoid[G, E]
}

func (g *MultiplicativeGroup[G, E]) Div(x algebra.MultiplicativeGroupElement[G, E], ys ...algebra.MultiplicativeGroupElement[G, E]) (E, error) {
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
	GroupElement[G, E]
	MultiplicativeMonoidElement[G, E]
}

func (e *MultiplicativeGroupElement[G, E]) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[G, E]) bool {
	return e.Unwrap().Mul(of).IsMultiplicativeIdentity()
}

func (e *MultiplicativeGroupElement[G, E]) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	// cursor := new(saferith.Nat).SetBytes(order.Bytes())
	// result := e.Clone()
	// for cursor.EqZero() == 0 {
	// 	result = result.Mul(e.Structure().AdditiveIdentity())
	// 	cursor = utils.DecrementNat(cursor)
	// }

	// return result.IsAdditiveIdentity()
	return true
}

func (e *MultiplicativeGroupElement[G, E]) ApplyDiv(x algebra.MultiplicativeGroupElement[G, E], n *saferith.Nat) E {
	// cursor := new(saferith.Nat).SetUint64(1)
	// res := e.Clone()
	// for cursor.Eq(n) != 1 {
	// 	res = res.Sub(x)
	// 	cursor = utils.IncrementNat(cursor)
	// }
	// return res
	return e.Unwrap()
}

type CyclicGroup[G algebra.CyclicGroup[G, E], E algebra.CyclicGroupElement[G, E]] struct {
	algebra.CyclicGroup[G, E]
	Group[G, E]
	CyclicGroupoid[G, E]
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
		exponent = utils.IncrementNat(exponent)
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

type CyclicGroupElement[G algebra.CyclicGroup[G, E], E algebra.CyclicGroupElement[G, E]] struct {
	algebra.CyclicGroupElement[G, E]
	GroupElement[G, E]
	CyclicGroupoidElement[G, E]
}

type AdditiveCyclicGroup[G algebra.AdditiveCyclicGroup[G, E], E algebra.AdditiveCyclicGroupElement[G, E]] struct {
	algebra.AdditiveCyclicGroup[G, E]
	CyclicGroup[G, E]
	AdditiveGroup[G, E]
}
