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

func NewIntegerUnitGroup[X modular.Arithmetic](modulus *num.NatPlus, arith X) (UnitGroup, error) {
	if modulus == nil {
		return nil, errs.NewIsNil("modulus")
	}
	zMod, err := num.NewZMod(modulus)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	return &UZMod[X]{
		DenseUZMod[X]{
			zMod:  zMod,
			arith: arith,
		},
	}, nil
}

type UZMod[X modular.Arithmetic] struct {
	DenseUZMod[X]
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
	return &unit{v: r, g: us}, nil
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
	out, err := us.DenseUZMod.FromNatCT(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from natct")
	}
	if !out.Value().Lift().Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	return out, nil
}

func (us *UZMod[X]) FromUint(input *num.Uint) (Unit, error) {
	out, err := us.DenseUZMod.FromUint(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from uint")
	}
	if !out.Value().Lift().Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	return out, nil
}

func (us *UZMod[X]) FromBytes(input []byte) (Unit, error) {
	out, err := us.DenseUZMod.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from bytes")
	}
	if !out.Value().Lift().Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	return out, nil
}

func (us *UZMod[X]) FromCardinal(input cardinal.Cardinal) (Unit, error) {
	out, err := us.DenseUZMod.FromCardinal(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from cardinal")
	}
	if !out.Value().Lift().Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	return out, nil
}

func (us *UZMod[X]) FromUint64(value uint64) (Unit, error) {
	out, err := us.DenseUZMod.FromUint64(value)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from uint64")
	}
	if !out.Value().Lift().Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	return out, nil
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

type DenseUZMod[X modular.Arithmetic] struct {
	zMod  *num.ZMod
	arith X
}

func (dus *DenseUZMod[X]) Name() string {
	return fmt.Sprintf("U(Z/%sZ)*", dus.Modulus().String())
}

func (dus *DenseUZMod[X]) Order() cardinal.Cardinal {
	return dus.arith.MultiplicativeOrder()
}

func (dus *DenseUZMod[X]) OpIdentity() Unit {
	return dus.One()
}

func (dus *DenseUZMod[X]) One() Unit {
	return &unit{v: dus.zMod.One(), g: dus}
}

func (dus *DenseUZMod[X]) Random(prng io.Reader) (Unit, error) {
	r, err := dus.zMod.Random(prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to generate random element")
	}
	return &unit{v: r, g: dus}, nil
}

func (dus *DenseUZMod[X]) Modulus() *num.NatPlus {
	return dus.zMod.Modulus()
}

func (dus *DenseUZMod[X]) ModulusCT() numct.Modulus {
	return dus.zMod.Modulus().ModulusCT()
}

func (dus *DenseUZMod[X]) ElementSize() int {
	return dus.zMod.ElementSize()
}

func (dus *DenseUZMod[X]) MultiScalarOp(scs []*num.Nat, ps []Unit) (Unit, error) {
	panic("implement me")
}

func (dus *DenseUZMod[X]) MultiScalarExp(scs []*num.Nat, ps []Unit) (Unit, error) {
	panic("implement me")
}

func (dus *DenseUZMod[X]) FromNatCT(input *numct.Nat) (Unit, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	elem, err := dus.zMod.FromNatCT(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from nat")
	}
	return &unit{v: elem, g: dus}, nil
}

func (dus *DenseUZMod[X]) FromUint(input *num.Uint) (Unit, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	if !dus.Modulus().Equal(input.Modulus()) {
		return nil, errs.NewValue("input is not in the same modulus")
	}
	return &unit{v: input.Clone(), g: dus}, nil
}

func (dus *DenseUZMod[X]) FromBytes(input []byte) (Unit, error) {
	if len(input) == 0 {
		return nil, errs.NewValue("input must not be empty")
	}
	v, err := dus.zMod.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit from bytes")
	}
	return &unit{v: v, g: dus}, nil
}

func (dus *DenseUZMod[X]) FromCardinal(input cardinal.Cardinal) (Unit, error) {
	elem, err := dus.zMod.FromCardinal(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from cardinal")
	}
	return &unit{v: elem, g: dus}, nil
}

func (dus *DenseUZMod[X]) FromUint64(value uint64) (Unit, error) {
	elem, err := dus.zMod.FromCardinal(cardinal.New(value))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from uint64")
	}
	return &unit{v: elem, g: dus}, nil
}

func (dus *DenseUZMod[X]) ScalarStructure() algebra.Structure[*num.Nat] {
	return num.N()
}

func (dus *DenseUZMod[X]) AmbientStructure() algebra.Structure[*num.Uint] {
	return dus.zMod
}

func (dus *DenseUZMod[X]) AmbientGroup() *num.ZMod {
	return dus.zMod
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
	v *num.Uint
	g UnitGroup
}

func (u *unit) Value() *num.Uint {
	return u.v
}

func (u *unit) ValueCT() *numct.Nat {
	return u.v.Value()
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
	return u.v.Equal(other.Value()) && u.EqualModulus(other)
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
	var out numct.Nat
	arithmeticOf(u).ModMul(&out, u.v.Value(), other.Value().Value())
	v, err := num.NewUintGivenModulus(&out, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	return &unit{v: v, g: u.g}
}

func (u *unit) Exp(exponent *num.Nat) Unit {
	var out numct.Nat
	arithmeticOf(u).ModExp(&out, u.v.Value(), exponent.Value())
	v, err := num.NewUintGivenModulus(&out, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	return &unit{v: v, g: u.g}
}

func (u *unit) ExpI(exponent *num.Int) Unit {
	var out numct.Nat
	arithmeticOf(u).ModExpInt(&out, u.v.Value(), exponent.Value())
	v, err := num.NewUintGivenModulus(&out, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	return &unit{v: v, g: u.g}
}

func (u *unit) Square() Unit {
	return &unit{v: u.v.Square(), g: u.g}
}

func (u *unit) TryInv() (Unit, error) {
	return u.Inv(), nil
}

func (u *unit) Inv() Unit {
	var out numct.Nat
	arithmeticOf(u).ModInv(&out, u.v.Value())
	v, err := num.NewUintGivenModulus(&out, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	return &unit{v: v, g: u.g}
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
	return u.v.IsOne()
}

func (u *unit) TryDiv(other Unit) (Unit, error) {
	return u.Div(other), nil
}

func (u *unit) Div(other Unit) Unit {
	if err := operandsAreValid(u, other); err != nil {
		panic(err)
	}
	var out numct.Nat
	arithmeticOf(u).ModDiv(&out, u.v.Value(), other.Value().Value())
	v, err := num.NewUintGivenModulus(&out, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	return &unit{v: v, g: u.g}
}

func (u *unit) HashCode() base.HashCode {
	return u.v.HashCode().Combine(u.v.HashCode())
}

func (u *unit) IsTorsionFree() bool {
	return true
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
