package group

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferith_utils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/cronokirby/saferith"
)

type GroupElement[G algebra.Group[G, E], E algebra.GroupElement[G, E]] struct {
	monoid.MonoidElement[G, E]
	H HolesGroupElement[G, E]
}

func (e *GroupElement[G, E]) IsInverse(of algebra.GroupElement[G, E], under algebra.Operator) (bool, error) {
	op, defined := e.H.Structure().GetOperator(under)
	if !defined {
		return false, errs.NewType("invalid operator")
	}
	image, err := op.Map(e.H.Unwrap(), of.Unwrap())
	if err != nil {
		return false, errs.WrapFailed(err, "could not apply the given operator")
	}
	return image.IsIdentity(under) //nolint:wrapcheck // forwarding errors
}

func (e *GroupElement[G, E]) IsTorsionElement(order *saferith.Modulus, under algebra.Operator) (bool, error) {
	op, defined := e.H.Structure().GetOperator(under)
	if !defined {
		return false, errs.NewType("invalid operator")
	}
	var err error
	cursor := new(saferith.Nat).SetBytes(order.Bytes())
	result := e.H.Clone()
	for cursor.EqZero() == 0 {
		result, err = op.Map(result, e.H.Unwrap())
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

func (e *GroupElement[G, E]) IsInvolution(under algebra.Operator) (bool, error) {
	return e.IsInverse(e.H.Unwrap(), under) //nolint:wrapcheck // forwarding errors
}

type AdditiveGroupElement[G algebra.AdditiveGroup[G, E], E algebra.AdditiveGroupElement[G, E]] struct {
	GroupElement[G, E]
	monoid.AdditiveMonoidElement[G, E]
	H HolesAdditiveGroupElement[G, E]
}

func (e *AdditiveGroupElement[G, E]) IsAdditiveInverse(of algebra.AdditiveGroupElement[G, E]) bool {
	return e.H.Add(of).IsAdditiveIdentity()
}

func (e *AdditiveGroupElement[G, E]) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	result, err := e.IsTorsionElement(order, e.H.Structure().Addition().Name())
	if err != nil {
		panic(errs.WrapFailed(err, "malformed additive group"))
	}
	return result
}

func (e *AdditiveGroupElement[G, E]) Neg() E {
	return e.H.AdditiveInverse()
}

func (e *AdditiveGroupElement[G, E]) Sub(x algebra.AdditiveGroupElement[G, E]) E {
	return e.H.Add(x.AdditiveInverse())
}

func (e *AdditiveGroupElement[G, E]) ApplySub(x algebra.AdditiveGroupElement[G, E], n *saferith.Nat) E {
	return e.ApplyAdd(x.AdditiveInverse(), n)
}

func (e *AdditiveGroupElement[G, E]) IsInvolutionUnderAddition() bool {
	return e.IsAdditiveInverse(e.H.Unwrap())
}

type MultiplicativeGroupElement[G algebra.MultiplicativeGroup[G, E], E algebra.MultiplicativeGroupElement[G, E]] struct {
	GroupElement[G, E]
	monoid.MultiplicativeMonoidElement[G, E]
	H HolesMultiplicativeGroupElement[G, E]
}

func (e *MultiplicativeGroupElement[G, E]) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[G, E]) bool {
	return e.H.Mul(of).IsMultiplicativeIdentity()
}

func (e *MultiplicativeGroupElement[G, E]) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	result, err := e.IsTorsionElement(order, e.H.Structure().Multiplication().Name())
	if err != nil {
		panic(errs.WrapFailed(err, "malformed multiplicative group"))
	}
	return result
}

func (e *MultiplicativeGroupElement[G, E]) Div(x algebra.MultiplicativeGroupElement[G, E]) (E, error) {
	xInv, err := x.MultiplicativeInverse()
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not compute multiplicative inverse of the argument")
	}
	return e.H.Mul(xInv), nil
}

func (e *MultiplicativeGroupElement[G, E]) ApplyDiv(x algebra.MultiplicativeGroupElement[G, E], n *saferith.Nat) (E, error) {
	xInv, err := x.MultiplicativeInverse()
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not derive multiplicative inverse of x")
	}
	return e.ApplyMul(xInv, n), nil
}

func (e *MultiplicativeGroupElement[G, E]) IsInvolutionUnderMultiplication() bool {
	return e.IsMultiplicativeInverse(e.H.Unwrap())
}

type CyclicGroupElement[G algebra.CyclicGroup[G, E], E algebra.CyclicGroupElement[G, E]] struct {
	GroupElement[G, E]
	monoid.CyclicMonoidElement[G, E]
	H HolesCyclicGroupElement[G, E]
}
