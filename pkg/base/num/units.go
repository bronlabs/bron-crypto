package num

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var (
	_ groups.MultiplicativeGroup[*Unit[*Uint]]          = (*UnitGroup[*Uint])(nil)
	_ groups.MultiplicativeGroup[*Unit[*ResidueNumber]] = (*UnitGroup[*ResidueNumber])(nil)

	_ groups.MultiplicativeGroupElement[*Unit[*Uint]]          = (*Unit[*Uint])(nil)
	_ groups.MultiplicativeGroupElement[*Unit[*ResidueNumber]] = (*Unit[*ResidueNumber])(nil)

	_ algebra.MultiplicativeModule[*Unit[*Uint], *Int]                 = (*UnitGroup[*Uint])(nil)
	_ algebra.MultiplicativeModuleElement[*Unit[*Uint], *Int]          = (*Unit[*Uint])(nil)
	_ algebra.MultiplicativeModule[*Unit[*ResidueNumber], *Int]        = (*UnitGroup[*ResidueNumber])(nil)
	_ algebra.MultiplicativeModuleElement[*Unit[*ResidueNumber], *Int] = (*Unit[*ResidueNumber])(nil)
)

func NewUnitGroup[E algebra.UintLike[E]](zn algebra.ZnLike[E], factors *PrimeFactorisation[E]) (*UnitGroup[E], error) {
	if factors == nil {
		return nil, fmt.Errorf("factors cannot be nil")
	}
	order, err := EulerTotient(factors)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compute order")
	}
	if zn.Characteristic().Eq(factors.N().SafeNat()) != 1 {
		return nil, errs.WrapFailed(errs.NewFailed("characteristic of Zn does not match the modulus"), "Zn: %s", zn.Name())
	}
	return &UnitGroup[E]{zn: zn, order: &order.v}, nil
}

func NewUnitGroupOfUnknownOrder[E algebra.UintLike[E]](zn algebra.ZnLike[E]) (*UnitGroup[E], error) {
	if zn == nil {
		return nil, errs.NewIsNil("zn")
	}
	return &UnitGroup[E]{zn: zn, order: algebra.Unknown}, nil
}

type UnitGroup[E algebra.UintLike[E]] struct {
	zn    algebra.ZnLike[E]
	order algebra.Cardinal
}

func (g *UnitGroup[E]) Name() string {
	return fmt.Sprintf("(Z/%sZ)*", g.Modulus().String())
}

func (g *UnitGroup[E]) Operator() algebra.BinaryOperator[*Unit[E]] {
	return algebra.Mul[*Unit[E]]
}

func (g *UnitGroup[E]) Order() algebra.Cardinal {
	return g.order
}

func (g *UnitGroup[E]) OpIdentity() *Unit[E] {
	return g.One()
}

func (g *UnitGroup[E]) One() *Unit[E] {
	return &Unit[E]{v: g.zn.One(), g: g}
}

func (g *UnitGroup[E]) Modulus() *NatPlus {
	return &NatPlus{v: *g.zn.Characteristic()}
}

type Unit[E algebra.UintLike[E]] struct {
	v algebra.UintLike[E]
	g *UnitGroup[E]
}

func (u *Unit[E]) SameModulus(other *Unit[E]) bool {
	if other == nil {
		panic("argument is nil")
	}
	return u.g.Modulus().Equal(other.g.Modulus())
}

func (u *Unit[E]) Structure() algebra.Structure[*Unit[E]] {
	return u.g
}

func (u *Unit[E]) Equal(other *Unit[E]) bool {
	if other == nil {
		panic("argument is nil")
	}
	otherV, ok := other.v.(E)
	if !ok {
		panic(errs.NewType("type error"))
	}
	return u.v.Equal(otherV)
}

func (u *Unit[E]) Clone() *Unit[E] {
	return &Unit[E]{v: u.v.Clone()}
}

func (u *Unit[E]) Op(other *Unit[E]) *Unit[E] {
	if other == nil {
		panic("argument is nil")
	}
	return u.Mul(other)
}

func (u *Unit[E]) Mul(other *Unit[E]) *Unit[E] {
	if !u.SameModulus(other) {
		panic(errs.NewFailed("moduli do not match: %s != %s", u.g.Modulus().String(), other.g.Modulus().String()))
	}
	return &Unit[E]{u.v.Mul(other.v.(E)), u.g}
}

func (u *Unit[E]) Exp(other *Unit[E]) *Unit[E] {
	if !u.SameModulus(other) {
		panic(errs.NewFailed("moduli do not match: %s != %s", u.g.Modulus().String(), other.g.Modulus().String()))
	}
	return &Unit[E]{u.v.Exp(other.v.(E)), u.g}
}

func (u *Unit[E]) Square() *Unit[E] {
	return &Unit[E]{u.v.Square(), u.g}
}

func (u *Unit[E]) TryInv() (*Unit[E], error) {
	return u.Inv(), nil
}

func (u *Unit[E]) Inv() *Unit[E] {
	out, err := u.v.TryInv()
	if err != nil {
		panic(err)
	}
	return &Unit[E]{out, u.g}
}

func (u *Unit[E]) TryOpInv() (*Unit[E], error) {
	return u.Inv(), nil
}

func (u *Unit[E]) OpInv() *Unit[E] {
	return u.Inv()
}

func (u *Unit[E]) IsOpIdentity() bool {
	return u.IsOne()
}

func (u *Unit[E]) IsOne() bool {
	return u.v.IsOne()
}

func (u *Unit[E]) TryDiv(other *Unit[E]) (*Unit[E], error) {
	return u.Div(other), nil
}

func (u *Unit[E]) Div(other *Unit[E]) *Unit[E] {
	if !u.SameModulus(other) {
		panic(errs.NewFailed("moduli do not match: %s != %s", u.g.Modulus().String(), other.g.Modulus().String()))
	}
	out, err := u.v.TryDiv(other.v.(E))
	if err != nil {
		panic(err)
	}
	return &Unit[E]{out, u.g}
}

func (u *Unit[E]) HashCode() uint64 {
	return u.v.HashCode()
}

func (u *Unit[E]) ScalarOp(scalar *Int) *Unit[E] {
	return u.ScalarExp(scalar)
}

func (u *Unit[E]) IsTorsionFree() bool {
	panic("implement me")
}

func (u *Unit[E]) ScalarExp(sc *Int) *Unit[E] {
	shouldInvert := sc.IsNegative()
	exponent, err := u.g.zn.FromSafeNat(&sc.Abs().v)
	if err != nil {
		panic(err)
	}
	out := u.v.Exp(exponent)
	if shouldInvert {
		out, err = out.TryInv()
		if err != nil {
			panic(err)
		}
	}
	return &Unit[E]{out, u.g}
}

func (u *Unit[E]) MarshalBinary() ([]byte, error) {
	panic("implement me")
}

func (u *Unit[E]) UnmarshalBinary(data []byte) error {
	panic("implement me")
}

type PlainUnit = *Unit[*Uint]
type FactoredUnit = *Unit[*ResidueNumber]
