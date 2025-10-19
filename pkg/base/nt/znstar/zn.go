package znstar

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// func NewUnitGroupOfUnknownOrder[X modular.Arithmetic](m *num.NatPlus) (*UZMod[X], error) {
// 	zMod, err := num.NewZMod(m)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create ZMod")
// 	}
// 	return &UZMod[X]{
// 		zMod:  zMod,
// 		order: cardinal.Unknown(),
// 	}, nil
// }.

// func NewUnitGroup[X modular.Arithmetic](arith X) (*UZMod[X], error) {
// 	if utils.IsNil(arith) {
// 		return nil, errs.NewIsNil("arith")
// 	}
// 	zMod, err := num.NewZModFromModulus(arith.Modulus())
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create ZMod")
// 	}
// 	return &UZMod[X]{
// 		zMod:  zMod,
// 		order: arith.MultiplicativeOrder(),
// 		arith: arith,
// 	}, nil
// }.

// func NewUnit[X modular.Arithmetic](v *num.Uint, g *UZMod[X]) (Unit, error) {
// 	if v == nil {
// 		return nil, errs.NewValue("v must not be nil")
// 	}
// 	if g == nil {
// 		return nil, errs.NewValue("g must not be nil")
// 	}
// 	if !v.Nat().Coprime(g.Modulus().Nat()) {
// 		return nil, errs.NewValue("v is not coprime to modulus")
// 	}
// 	if !v.Modulus().Equal(g.Modulus()) {
// 		return nil, errs.NewValue("v is not in the same modulus as g")
// 	}
// 	return &unit{v: v.Clone().Value(), g: g}, nil
// }.

type UZMod[X modular.Arithmetic] struct {
	zMod  *num.ZMod
	arith X
}

func (us *UZMod[X]) Name() string {
	return fmt.Sprintf("U(Z/%sZ)*", us.Modulus().String())
}

func (us *UZMod[X]) Order() cardinal.Cardinal {
	return us.arith.MultiplicativeOrder()
}

func (us *UZMod[X]) OpIdentity() Unit {
	return us.One()
}

func (us *UZMod[X]) One() Unit {
	return &unit{v: us.zMod.One().Value(), g: us}
}

func (us *UZMod[X]) Random(prng io.Reader) (Unit, error) {
	r, err := us.zMod.Random(prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to generate random element")
	}
	for !r.IsUnit() {
		r, err = us.zMod.Random(prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to generate random element")
		}
	}
	return &unit{v: r.Value(), g: us}, nil
}

func (us *UZMod[X]) Modulus() *num.NatPlus {
	return us.zMod.Modulus()
}

func (us *UZMod[X]) ModulusCT() numct.Modulus {
	return us.zMod.Modulus().ModulusCT()
}

func (us *UZMod[X]) ElementSize() int {
	return us.zMod.ElementSize()
}

func (us *UZMod[X]) MultiScalarOp(scs []*num.Nat, ps []Unit) (Unit, error) {
	panic("implement me")
}

func (us *UZMod[X]) MultiScalarExp(scs []*num.Nat, ps []Unit) (Unit, error) {
	panic("implement me")
}

func (us *UZMod[X]) FromNatCT(input *numct.Nat) (Unit, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	if input.Coprime(us.ModulusCT().Nat()) == ct.False {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	elem, err := us.zMod.FromNatCT(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from nat")
	}
	return &unit{v: elem.Value(), g: us}, nil
}

func (us *UZMod[X]) FromUint(input *num.Uint) (Unit, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	if !us.Modulus().Equal(input.Modulus()) {
		return nil, errs.NewValue("input is not in the same modulus")
	}
	if !input.Abs().Coprime(us.Modulus().Nat()) {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	return &unit{v: input.Clone().Value(), g: us}, nil
}

func (us *UZMod[X]) FromBytes(input []byte) (Unit, error) {
	if len(input) == 0 {
		return nil, errs.NewValue("input must not be empty")
	}
	t, err := num.Z().FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create integer from bytes")
	}
	if !t.Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	v, err := us.zMod.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit from bytes")
	}
	return &unit{v: v.Value(), g: us}, nil
}

func (us *UZMod[X]) FromCardinal(input cardinal.Cardinal) (Unit, error) {
	elem, err := us.zMod.FromCardinal(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from cardinal")
	}
	t, err := num.Z().FromCardinal(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create integer from cardinal")
	}
	if !t.Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("element is not coprime to modulus")
	}
	return &unit{v: elem.Value(), g: us}, nil
}

func (us *UZMod[X]) FromUint64(value uint64) (Unit, error) {
	if !num.Z().FromUint64(value).Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("value is not coprime to modulus")
	}
	elem, err := us.zMod.FromCardinal(cardinal.New(value))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from uint64")
	}
	return &unit{v: elem.Value(), g: us}, nil
}

func (us *UZMod[X]) ScalarStructure() algebra.Structure[*num.Nat] {
	return num.N()
}

func (us *UZMod[X]) AmbientStructure() algebra.Structure[*num.Uint] {
	return us.zMod
}

func (us *UZMod[X]) AmbientGroup() *num.ZMod {
	return us.zMod
}

// ======= Units =======.

func operandsAreValid(x, y Unit) error {
	if x == nil {
		return errs.NewIsNil("x")
	}
	if y == nil {
		return errs.NewIsNil("y")
	}
	if !x.Modulus().Equal(y.Modulus()) {
		return errs.NewValue("x and y must have the same modulus")
	}
	if x.IsUnknownOrder() != y.IsUnknownOrder() {
		return errs.NewValue("x and y must both be in known or unknown order groups")
	}
	return nil
}

func arithmeticOf(u Unit) modular.Arithmetic {
	var arith modular.Arithmetic
	var err error
	if u.IsUnknownOrder() {
		var ok ct.Bool
		arith, ok = modular.NewSimple(u.ModulusCT())
		if ok == ct.False {
			err = errs.NewFailed("failed to create SimpleModulus")
		}
	} else if gRsa, ok := u.Group().(RSAGroupKnownOrder); ok {
		arith = gRsa.Arithmetic()
	} else if gPail, ok := u.Group().(PaillierGroupKnownOrder); ok {
		arith = gPail.Arithmetic()
	} else {
		panic("cannot get arithmetic for this group")
	}
	if err != nil {
		panic(err)
	}
	return arith
}

type unit struct {
	v *numct.Nat
	g UnitGroup
}

func (u *unit) Value() *numct.Nat {
	return u.v
}

func (u *unit) IsUnknownOrder() bool {
	return u.Structure().Order().IsUnknown()
}

func (u *unit) ForgetOrder() Unit {
	out := &unit{v: u.v.Clone(), g: u.g}
	if u.IsUnknownOrder() {
		return out
	}
	if gRsa, ok := u.g.(*rsaGroupKnownOrder); ok {
		out.g = gRsa.ForgetOrder()
		return out
	}
	if gPail, ok := u.g.(*paillierGroupKnownOrder); ok {
		out.g = gPail.ForgetOrder()
		return out
	}
	panic(fmt.Sprintf("cannot forget order of this group (type: %T)", u.g))
}

func (u *unit) LearnOrder(g UnitGroup) Unit {
	if !u.Modulus().Equal(g.Modulus()) {
		panic("cannot learn order in a different group")
	}
	out := u.Clone().(*unit)
	if !g.Order().IsUnknown() {
		out.g = g
	}
	return out
}

func (u *unit) Modulus() *num.NatPlus {
	return u.g.Modulus()
}

func (u *unit) ModulusCT() numct.Modulus {
	return u.g.ModulusCT()
}

func (u *unit) EqualModulus(other Unit) bool {
	return other != nil && u.Modulus().Equal(other.Modulus())
}

func (u *unit) Group() UnitGroup {
	return u.g
}

func (u *unit) Structure() algebra.Structure[Unit] {
	return u.g
}

func (u *unit) Equal(other Unit) bool {
	return u.v.Equal(other.Value()) == ct.True && u.EqualModulus(other)
}

func (u *unit) Clone() Unit {
	return &unit{v: u.v.Clone(), g: u.g}
}

func (u *unit) Op(other Unit) Unit {
	return u.Mul(other)
}

func (u *unit) Mul(other Unit) Unit {
	if err := operandsAreValid(u, other); err != nil {
		panic(err)
	}
	out := numct.NewNat(0)
	arithmeticOf(u).ModMul(out, u.v, other.Value())
	return &unit{v: out, g: u.g}
}

func (u *unit) Exp(exponent *num.Nat) Unit {
	out := numct.NewNat(0)
	arithmeticOf(u).ModExp(out, u.v, exponent.Value())
	return &unit{v: out, g: u.g}
}

func (u *unit) ExpI(exponent *num.Int) Unit {
	if exponent.IsNegative() {
		out := numct.NewNat(0)
		u.ModulusCT().ModExpInt(out, u.v, exponent.Value())
		return &unit{v: out, g: u.g}
	} else {
		return u.Exp(exponent.Abs())
	}
}

func (u *unit) Square() Unit {
	v := u.v.Clone()
	v.Mul(u.v, u.v)
	return &unit{v: v, g: u.g}
}

func (u *unit) TryInv() (Unit, error) {
	return u.Inv(), nil
}

func (u *unit) Inv() Unit {
	out := numct.NewNat(0)
	arithmeticOf(u).ModInv(out, u.v)
	return &unit{v: out, g: u.g}
}

func (u *unit) TryOpInv() (Unit, error) {
	return u.Inv(), nil
}

func (u *unit) OpInv() Unit {
	return u.Inv()
}

func (u *unit) IsOpIdentity() bool {
	return u.IsOne()
}

func (u *unit) IsOne() bool {
	return u.v.IsOne() == ct.True
}

func (u *unit) TryDiv(other Unit) (Unit, error) {
	return u.Div(other), nil
}

func (u *unit) Div(other Unit) Unit {
	if err := operandsAreValid(u, other); err != nil {
		panic(err)
	}
	out := numct.NewNat(0)
	arithmeticOf(u).ModDiv(out, u.v, other.Value())
	return &unit{v: out, g: u.g}
}

func (u *unit) HashCode() base.HashCode {
	return u.v.HashCode().Combine(u.v.HashCode())
}

func (u *unit) IsTorsionFree() bool {
	panic("implement me")
}

func (u *unit) ScalarOp(scalar *num.Nat) Unit {
	return u.ScalarExp(scalar)
}

func (u *unit) ScalarExp(sc *num.Nat) Unit {
	return u.Exp(sc)
}

func (u *unit) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromBig(u.v.Big())
}

func (u *unit) Bytes() []byte {
	return u.v.Bytes()
}

func (u *unit) String() string {
	return u.v.String()
}
