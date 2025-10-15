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

type paillierUnitUnknownOrder struct {
	internal.UnitUnknownOrderTrait[*paillierGroup, *paillierUnitUnknownOrder, *paillierUnitUnknownOrder, paillierUnitUnknownOrder]
}

func (u *paillierUnitUnknownOrder) Clone() *paillierUnitUnknownOrder {
	return &paillierUnitUnknownOrder{
		UnitUnknownOrderTrait: internal.UnitUnknownOrderTrait[*paillierGroup, *paillierUnitUnknownOrder, *paillierUnitUnknownOrder, paillierUnitUnknownOrder]{
			V: u.V.Clone(),
			M: u.M,
			G: u.G,
		},
	}
}

func (u *paillierUnitUnknownOrder) Structure() algebra.Structure[*paillierUnitUnknownOrder] {
	panic("Structure method of the union should have been called")
}

type paillierUnitKnownOrder struct {
	internal.UnitKnownOrderTrait[*modular.OddPrimeSquareFactors, *paillierGroup, *paillierUnitUnknownOrder, *paillierUnitUnknownOrder, paillierUnitKnownOrder]
}

func (u *paillierUnitKnownOrder) Clone() *paillierUnitKnownOrder {
	return &paillierUnitKnownOrder{
		UnitKnownOrderTrait: internal.UnitKnownOrderTrait[*modular.OddPrimeSquareFactors, *paillierGroup, *paillierUnitUnknownOrder, *paillierUnitUnknownOrder, paillierUnitKnownOrder]{
			V: u.V.Clone(),
			M: u.M,
			G: u.G,
		},
	}
}

func (u *paillierUnitKnownOrder) Structure() algebra.Structure[*paillierUnitKnownOrder] {
	panic("Structure method of the union should have been called")
}

type paillierUnitUnioned[U Unit[U]] struct {
	v U
}

func (u *paillierUnitUnioned[U]) ForgetOrder() PaillierUnit {
	return &paillierUnitUnioned[U]{v: u.v.ForgetOrder()}
}

func (u *paillierUnitUnioned[U]) Value() *numct.Nat {
	return u.v.Value()
}

func (u *paillierUnitUnioned[U]) IsUnknownOrder() bool {
	return u.v.IsUnknownOrder()
}

func (u *paillierUnitUnioned[U]) Modulus() *num.NatPlus {
	return u.v.Modulus()
}

func (u *paillierUnitUnioned[U]) ModulusCT() numct.Modulus {
	return u.v.ModulusCT()
}

func (u *paillierUnitUnioned[U]) EqualModulus(other PaillierUnit) bool {
	uu, ok := other.(*paillierUnitUnioned[U])
	return ok && u.v.EqualModulus(uu.v)
}

func (u *paillierUnitUnioned[U]) Equal(other PaillierUnit) bool {
	uu, ok := other.(*paillierUnitUnioned[U])
	return ok && u.v.Equal(uu.v)
}

func (u *paillierUnitUnioned[U]) Op(other PaillierUnit) PaillierUnit {
	return u.Mul(other)
}

func (u *paillierUnitUnioned[U]) Mul(other PaillierUnit) PaillierUnit {
	uu, ok := other.(*paillierUnitUnioned[U])
	if !ok {
		panic("other is not of the same type")
	}
	return &paillierUnitUnioned[U]{v: u.v.Mul(uu.v)}
}

func (u *paillierUnitUnioned[U]) Exp(e *num.Nat) PaillierUnit {
	return &paillierUnitUnioned[U]{v: u.v.Exp(e)}
}

func (u *paillierUnitUnioned[U]) ExpI(e *num.Int) PaillierUnit {
	return &paillierUnitUnioned[U]{v: u.v.ExpI(e)}
}

func (u *paillierUnitUnioned[U]) Square() PaillierUnit {
	return &paillierUnitUnioned[U]{v: u.v.Square()}
}

func (u *paillierUnitUnioned[U]) TryInv() (PaillierUnit, error) {
	return u.Inv(), nil
}

func (u *paillierUnitUnioned[U]) Inv() PaillierUnit {
	return &paillierUnitUnioned[U]{v: u.v.Inv()}
}

func (u *paillierUnitUnioned[U]) TryOpInv() (PaillierUnit, error) {
	return u.OpInv(), nil
}

func (u *paillierUnitUnioned[U]) OpInv() PaillierUnit {
	return &paillierUnitUnioned[U]{v: u.v.OpInv()}
}

func (u *paillierUnitUnioned[U]) IsOpIdentity() bool {
	return u.v.IsOpIdentity()
}

func (u *paillierUnitUnioned[U]) IsOne() bool {
	return u.v.IsOne()
}

func (u *paillierUnitUnioned[U]) TryDiv(other PaillierUnit) (PaillierUnit, error) {
	return u.Div(other), nil
}

func (u *paillierUnitUnioned[U]) Div(other PaillierUnit) PaillierUnit {
	uu, ok := other.(*paillierUnitUnioned[U])
	if !ok {
		panic("other is not of the same type")
	}
	return &paillierUnitUnioned[U]{v: u.v.Div(uu.v)}
}

func (u *paillierUnitUnioned[U]) HashCode() base.HashCode {
	return u.v.HashCode()
}

func (u *paillierUnitUnioned[U]) IsTorsionFree() bool {
	return u.v.IsTorsionFree()
}

func (u *paillierUnitUnioned[U]) Clone() PaillierUnit {
	return &paillierUnitUnioned[U]{v: u.v.Clone()}
}

func (u *paillierUnitUnioned[U]) Structure() algebra.Structure[PaillierUnit] {
	return u.v.Structure()
}

func (u *paillierUnitUnioned[U]) String() string {
	return u.v.String()
}

func (u *paillierUnitUnioned[U]) ScalarOp(s *num.Nat) PaillierUnit {
	return &paillierUnitUnioned[U]{v: u.v.ScalarOp(s)}
}

func (u *paillierUnitUnioned[U]) ScalarExp(s *num.Nat) PaillierUnit {
	return u.Exp(s)
}

func (u *paillierUnitUnioned[U]) Cardinal() cardinal.Cardinal {
	return u.v.Cardinal()
}

func (u *paillierUnitUnioned[U]) Bytes() []byte {
	return u.v.Bytes()
}

func _[U Unit[U]]() {
	var (
		_ PaillierUnit = &paillierUnitUnioned[U]{}
	)
}
