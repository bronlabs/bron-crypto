package internal

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type UnitKnownOrderTrait[X modular.Arithmetic, G interface {
	// UnitGroup[U]
	Order() cardinal.Cardinal
	Modulus() *num.NatPlus
	ModulusCT() numct.Modulus
	KnowledgeOfOrderCrtp[X, GF]
}, U Unit[U], GF any, W UnitPtrConstraint[G, U, WT], WT any] struct {
	V *numct.Nat
	M numct.Modulus
	G G
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) setValue(v *numct.Nat) {
	u.V = v.Clone()
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) setModulus(m numct.Modulus) {
	u.M = m
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) setGroup(g G) {
	u.G = g
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Value() *numct.Nat {
	return u.V
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) IsUnknownOrder() bool {
	return u.G.Order().IsUnknown()
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Modulus() *num.NatPlus {
	return u.G.Modulus()
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) ModulusCT() numct.Modulus {
	return u.G.ModulusCT()
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) EqualModulus(other W) bool {
	return other != nil && u.Modulus().Equal(other.Modulus())
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Group() G {
	return u.G
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Equal(other W) bool {
	return u.V.Equal(other.Value()) == ct.True && u.EqualModulus(other)
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Op(other W) W {
	return u.Mul(other)
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Mul(other W) W {
	if err := OperandsAreValid(u, other); err != nil {
		panic(err)
	}
	outV := numct.NewNat(0)
	u.G.Arithmetic().ModMul(outV, u.V, other.Value())
	var out WT
	W(&out).setValue(outV)
	W(&out).setGroup(u.G)
	W(&out).setModulus(u.ModulusCT())
	return &out
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Exp(exponent *num.Nat) W {
	outV := numct.NewNat(0)
	u.G.Arithmetic().ModExp(outV, u.V, exponent.Value())
	var out WT
	W(&out).setValue(outV)
	W(&out).setGroup(u.G)
	W(&out).setModulus(u.ModulusCT())
	return &out
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) ExpI(exponent *num.Int) W {
	if exponent.IsNegative() {
		outV := numct.NewNat(0)
		u.ModulusCT().ModExpInt(outV, u.V, exponent.Value())
		var out WT
		W(&out).setValue(outV)
		W(&out).setModulus(u.ModulusCT())
		W(&out).setGroup(u.G)
		return &out
	} else {
		return u.Exp(exponent.Abs())
	}
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Square() W {
	v := u.V.Clone()
	v.Mul(u.V, u.V)
	var out WT
	W(&out).setValue(v)
	W(&out).setModulus(u.ModulusCT())
	W(&out).setGroup(u.G)
	return &out
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) TryInv() (W, error) {
	return u.Inv(), nil
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Inv() W {
	outV := numct.NewNat(0)
	u.G.Arithmetic().ModInv(outV, u.V)
	var out WT
	W(&out).setValue(outV)
	W(&out).setModulus(u.ModulusCT())
	W(&out).setGroup(u.G)
	return &out
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) TryOpInv() (W, error) {
	return u.Inv(), nil
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) OpInv() W {
	return u.Inv()
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) IsOpIdentity() bool {
	return u.IsOne()
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) IsOne() bool {
	return u.V.IsOne() == ct.True
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) TryDiv(other W) (W, error) {
	return u.Div(other), nil
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Div(other W) W {
	if err := OperandsAreValid(u, other); err != nil {
		panic(err)
	}
	outV := numct.NewNat(0)
	u.G.Arithmetic().ModDiv(outV, u.V, other.Value())
	var out WT
	W(&out).setValue(outV)
	W(&out).setModulus(u.ModulusCT())
	W(&out).setGroup(u.G)
	return &out
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) HashCode() base.HashCode {
	return u.V.HashCode().Combine(u.V.HashCode())
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) IsTorsionFree() bool {
	panic("implement me")
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) ScalarOp(scalar *num.Nat) W {
	return u.ScalarExp(scalar)
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) ScalarExp(sc *num.Nat) W {
	return u.Exp(sc)
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromBig(u.V.Big())
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) Bytes() []byte {
	return u.V.Bytes()
}

func (u *UnitKnownOrderTrait[X, G, U, GF, W, WT]) String() string {
	return u.V.String()
}
