package internal

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type UnitUnknownOrderTrait[G UnitGroup[U], U Unit[U], W UnitPtrConstraint[G, U, WT], WT any] struct {
	V *numct.Nat
	M numct.Modulus
	G G
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) setValue(v *numct.Nat) {
	u.V = v.Clone()
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) setModulus(m numct.Modulus) {
	u.M = m
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) setGroup(g G) {
	u.G = g
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) ForgetOrder() W {
	var self WT
	W(&self).setValue(u.V)
	W(&self).setModulus(u.M)
	W(&self).setGroup(u.G)
	return &self
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Value() *numct.Nat {
	return u.V
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) IsUnknownOrder() bool {
	return true
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Modulus() *num.NatPlus {
	return num.NPlus().FromModulus(u.M)
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) ModulusCT() numct.Modulus {
	return u.M
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) EqualModulus(other W) bool {
	return other != nil && u.Modulus().Equal(other.Modulus())
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Group() G {
	return u.G
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Equal(other W) bool {
	return u.V.Equal(other.Value()) == ct.True && u.EqualModulus(other)
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Op(other W) W {
	return u.Mul(other)
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Mul(other W) W {
	if err := OperandsAreValid(u, other); err != nil {
		panic(err)
	}
	outV := numct.NewNat(0)
	u.ModulusCT().ModMul(outV, u.V, other.Value())
	var out WT
	W(&out).setValue(outV)
	W(&out).setModulus(u.M)
	W(&out).setGroup(u.G)
	return &out
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Exp(exponent *num.Nat) W {
	outV := numct.NewNat(0)
	u.ModulusCT().ModExp(outV, u.V, exponent.Value())
	var out WT
	W(&out).setValue(outV)
	W(&out).setModulus(u.M)
	W(&out).setGroup(u.G)
	return &out
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) ExpI(exponent *num.Int) W {
	outV := numct.NewNat(0)
	u.ModulusCT().ModExpInt(outV, u.V, exponent.Value())
	var out WT
	W(&out).setValue(outV)
	W(&out).setModulus(u.M)
	W(&out).setGroup(u.G)
	return &out
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Square() W {
	v := u.V.Clone()
	v.Mul(u.V, u.V)
	var out WT
	W(&out).setValue(v)
	W(&out).setModulus(u.M)
	W(&out).setGroup(u.G)
	return &out
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) TryInv() (W, error) {
	return u.Inv(), nil
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Inv() W {
	outV := numct.NewNat(0)
	u.ModulusCT().ModInv(outV, u.V)
	var out WT
	W(&out).setValue(outV)
	W(&out).setModulus(u.M)
	W(&out).setGroup(u.G)
	return &out
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) TryOpInv() (W, error) {
	return u.Inv(), nil
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) OpInv() W {
	return u.Inv()
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) IsOpIdentity() bool {
	return u.IsOne()
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) IsOne() bool {
	return u.V.IsOne() == ct.True
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) TryDiv(other W) (W, error) {
	return u.Div(other), nil
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Div(other W) W {
	if err := OperandsAreValid(u, other); err != nil {
		panic(err)
	}
	outV := numct.NewNat(0)
	u.ModulusCT().ModDiv(outV, u.V, other.Value())
	var out WT
	W(&out).setValue(outV)
	W(&out).setModulus(u.M)
	W(&out).setGroup(u.G)
	return &out
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) HashCode() base.HashCode {
	return u.V.HashCode().Combine(u.V.HashCode())
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) IsTorsionFree() bool {
	panic("implement me")
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) ScalarOp(scalar *num.Nat) W {
	return u.ScalarExp(scalar)
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) ScalarExp(sc *num.Nat) W {
	return u.Exp(sc)
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromBig(u.V.Big())
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) Bytes() []byte {
	return u.V.Bytes()
}

func (u *UnitUnknownOrderTrait[G, U, W, WT]) String() string {
	return u.V.String()
}
