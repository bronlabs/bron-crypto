package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar/internal"
)

type rsaUnitUnknownOrder struct {
	internal.UnitUnknownOrderTrait[*rsaGroupUnknownOrder, *rsaUnitUnknownOrder, *rsaUnitUnknownOrder, rsaUnitUnknownOrder]
}

func (u *rsaUnitUnknownOrder) Clone() *rsaUnitUnknownOrder {
	return &rsaUnitUnknownOrder{
		UnitUnknownOrderTrait: internal.UnitUnknownOrderTrait[*rsaGroupUnknownOrder, *rsaUnitUnknownOrder, *rsaUnitUnknownOrder, rsaUnitUnknownOrder]{
			V: u.V.Clone(),
			M: u.M,
			G: u.G,
		},
	}
}

func (u *rsaUnitUnknownOrder) Structure() algebra.Structure[*rsaUnitUnknownOrder] {
	panic("Structure method of the union should have been called")
}

type rsaUnitKnownOrder struct {
	internal.UnitKnownOrderTrait[*modular.OddPrimeFactors, *rsaGroupKnownOrder, *rsaUnitKnownOrder, RSAGroup, *rsaUnitKnownOrder, rsaUnitKnownOrder]
}

func (u *rsaUnitKnownOrder) ForgetOrder() *rsaUnitUnknownOrder {
	return nil
}

func (u *rsaUnitKnownOrder) Clone() *rsaUnitKnownOrder {
	return nil
}

func (u *rsaUnitKnownOrder) Structure() algebra.Structure[*rsaUnitKnownOrder] {
	panic("Structure method of the union should have been called")
}

type rsaUnitUnioned[U Unit[U]] struct {
	v U
}

func (u *rsaUnitUnioned[U]) ForgetOrder() RSAUnit {
	group, ok := any(u.v.Structure()).(*rsaGroupKnownOrder)
	if !ok {
		panic("unit is not of the expected type")
	}
	v := &rsaUnitUnknownOrder{
		UnitUnknownOrderTrait: internal.UnitUnknownOrderTrait[*rsaGroupUnknownOrder, *rsaUnitUnknownOrder, *rsaUnitUnknownOrder, rsaUnitUnknownOrder]{
			V: u.v.Value().Clone(),
			M: u.v.ModulusCT(),
			G: group.ForgetOrder().(*rsaGroupUnknownOrder),
		},
	}
}

func (u *rsaUnitUnioned[U]) Value() *numct.Nat {
	return u.v.Value()
}

func (u *rsaUnitUnioned[U]) IsUnknownOrder() bool {
	return u.v.IsUnknownOrder()
}

func (u *rsaUnitUnioned[U]) Modulus() *num.NatPlus {
	return u.v.Modulus()
}

func (u *rsaUnitUnioned[U]) ModulusCT() numct.Modulus {
	return u.v.ModulusCT()
}

func (u *rsaUnitUnioned[U]) EqualModulus(other RSAUnit) bool {
	uu, ok := other.(*rsaUnitUnioned[U])
	return ok && u.v.EqualModulus(uu.v)
}

func (u *rsaUnitUnioned[U]) Equal(other RSAUnit) bool {
	uu, ok := other.(*rsaUnitUnioned[U])
	return ok && u.v.Equal(uu.v)
}

func (u *rsaUnitUnioned[U]) Op(other RSAUnit) RSAUnit {
	return u.Mul(other)
}

func (u *rsaUnitUnioned[U]) Mul(other RSAUnit) RSAUnit {
	uu, ok := other.(*rsaUnitUnioned[U])
	if !ok {
		panic("other is not of the same type")
	}
	return &rsaUnitUnioned[U]{v: u.v.Mul(uu.v)}
}

func (u *rsaUnitUnioned[U]) Exp(e *num.Nat) RSAUnit {
	return &rsaUnitUnioned[U]{v: u.v.Exp(e)}
}

func (u *rsaUnitUnioned[U]) ExpI(e *num.Int) RSAUnit {
	return &rsaUnitUnioned[U]{v: u.v.ExpI(e)}
}

func (u *rsaUnitUnioned[U]) Square() RSAUnit {
	return &rsaUnitUnioned[U]{v: u.v.Square()}
}

func (u *rsaUnitUnioned[U]) TryInv() (RSAUnit, error) {
	return u.Inv(), nil
}

func (u *rsaUnitUnioned[U]) Inv() RSAUnit {
	return &rsaUnitUnioned[U]{v: u.v.Inv()}
}

func (u *rsaUnitUnioned[U]) TryOpInv() (RSAUnit, error) {
	return u.OpInv(), nil
}

func (u *rsaUnitUnioned[U]) OpInv() RSAUnit {
	return &rsaUnitUnioned[U]{v: u.v.OpInv()}
}

func (u *rsaUnitUnioned[U]) IsOpIdentity() bool {
	return u.v.IsOpIdentity()
}

func (u *rsaUnitUnioned[U]) IsOne() bool {
	return u.v.IsOne()
}

func (u *rsaUnitUnioned[U]) TryDiv(other RSAUnit) (RSAUnit, error) {
	return u.Div(other), nil
}

func (u *rsaUnitUnioned[U]) Div(other RSAUnit) RSAUnit {
	uu, ok := other.(*rsaUnitUnioned[U])
	if !ok {
		panic("other is not of the same type")
	}
	return &rsaUnitUnioned[U]{v: u.v.Div(uu.v)}
}

func (u *rsaUnitUnioned[U]) HashCode() base.HashCode {
	return u.v.HashCode()
}

func (u *rsaUnitUnioned[U]) IsTorsionFree() bool {
	return u.v.IsTorsionFree()
}

func (u *rsaUnitUnioned[U]) Clone() RSAUnit {
	return &rsaUnitUnioned[U]{v: u.v.Clone()}
}

func (u *rsaUnitUnioned[U]) Structure() algebra.Structure[RSAUnit] {
	return u.v.Structure()
}

func (u *rsaUnitUnioned[U]) String() string {
	return u.v.String()
}

func (u *rsaUnitUnioned[U]) ScalarOp(s *num.Nat) RSAUnit {
	return &rsaUnitUnioned[U]{v: u.v.ScalarOp(s)}
}

func (u *rsaUnitUnioned[U]) ScalarExp(s *num.Nat) RSAUnit {
	return u.Exp(s)
}

func (u *rsaUnitUnioned[U]) Cardinal() cardinal.Cardinal {
	return u.v.Cardinal()
}

func (u *rsaUnitUnioned[U]) Bytes() []byte {
	return u.v.Bytes()
}

func _[U Unit[U]]() {
	var (
		_ RSAUnit = &rsaUnitUnioned[U]{}
	)
}
