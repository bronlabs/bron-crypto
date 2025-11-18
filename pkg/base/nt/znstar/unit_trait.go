package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type UnitTrait[A modular.Arithmetic, W unitWrapperPtrConstraint[A, WT], WT any] struct {
	v     *num.Uint
	arith A
	n     *num.NatPlus
}

func (u *UnitTrait[A, W, WT]) Value() *num.Uint {
	return u.v
}

func (u *UnitTrait[A, W, WT]) Arithmetic() A {
	return u.arith
}

func (u *UnitTrait[A, W, WT]) set(v *num.Uint, arith A, n *num.NatPlus) {
	u.v = v
	u.arith = arith
	u.n = n
}

func (u *UnitTrait[A, W, WT]) IsUnknownOrder() bool {
	return u.arith.MultiplicativeOrder().IsUnknown()
}

func (u *UnitTrait[A, W, WT]) Modulus() *num.NatPlus {
	return u.v.Modulus()
}

func (u *UnitTrait[A, W, WT]) ModulusCT() *numct.Modulus {
	return u.arith.Modulus()
}

func (u *UnitTrait[A, W, WT]) EqualModulus(other W) bool {
	return u.Modulus().Equal(other.Modulus())
}

func (u *UnitTrait[A, W, WT]) Equal(other W) bool {
	return u.v.Equal(other.Value()) && u.EqualModulus(other)
}

func (u *UnitTrait[A, W, WT]) Op(other W) W {
	return u.Mul(other)
}

func (u *UnitTrait[A, W, WT]) assertValidity(other W) {
	if !u.EqualModulus(other) {
		panic("cannot multiply units with different moduli")
	}
	if u.IsUnknownOrder() != other.IsUnknownOrder() {
		panic("cannot multiply units with different knowledge of order")
	}
}

func (u *UnitTrait[A, W, WT]) Mul(other W) W {
	u.assertValidity(other)
	var outCt numct.Nat
	u.arith.ModMul(&outCt, u.v.Value(), other.Value().Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) Exp(exponent *num.Nat) W {
	var outCt numct.Nat
	u.arith.ModExp(&outCt, u.v.Value(), exponent.Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) ExpBounded(exponent *num.Nat, bits uint) W {
	ex := exponent.Value().Clone()
	ex.Resize(int(bits))
	var outCt numct.Nat
	u.arith.ModExp(&outCt, u.v.Value(), ex)
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)

}

func (u *UnitTrait[A, W, WT]) ExpI(exponent *num.Int) W {
	var outCt numct.Nat
	u.arith.ModExpInt(&outCt, u.v.Value(), exponent.Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) ExpIBounded(exponent *num.Int, bits uint) W {
	ex := exponent.Value().Clone()
	ex.Resize(int(bits))
	var outCt numct.Nat
	u.arith.ModExpInt(&outCt, u.v.Value(), ex)
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)

}

func (u *UnitTrait[A, W, WT]) Square() W {
	var outCt numct.Nat
	u.arith.ModMul(&outCt, u.v.Value(), u.v.Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) TryInv() (W, error) {
	return u.Inv(), nil
}

func (u *UnitTrait[A, W, WT]) Inv() W {
	var outCt numct.Nat
	u.arith.ModInv(&outCt, u.v.Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) TryOpInv() (W, error) {
	return u.Inv(), nil
}

func (u *UnitTrait[A, W, WT]) OpInv() W {
	return u.Inv()
}

func (u *UnitTrait[A, W, WT]) IsOpIdentity() bool {
	return u.IsOne()
}

func (u *UnitTrait[A, W, WT]) IsOne() bool {
	return u.v.IsOne()
}

func (u *UnitTrait[A, W, WT]) TryDiv(other W) (W, error) {
	return u.Div(other), nil
}

func (u *UnitTrait[A, W, WT]) Div(other W) W {
	u.assertValidity(other)
	var outCt numct.Nat
	u.arith.ModDiv(&outCt, u.v.Value(), other.Value().Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) HashCode() base.HashCode {
	return u.v.HashCode().Combine(u.v.HashCode())
}

func (u *UnitTrait[A, W, WT]) IsTorsionFree() bool {
	return true
}

func (u *UnitTrait[A, W, WT]) ScalarOp(scalar *num.Nat) W {
	return u.Exp(scalar)
}

func (u *UnitTrait[A, W, WT]) ScalarExp(scalar *num.Nat) W {
	return u.Exp(scalar)
}

func (u *UnitTrait[A, W, WT]) Cardinal() cardinal.Cardinal {
	return u.v.Cardinal()
}

func (u *UnitTrait[A, W, WT]) Bytes() []byte {
	return u.v.Bytes()
}

func (u *UnitTrait[A, W, WT]) String() string {
	return u.v.String()
}
