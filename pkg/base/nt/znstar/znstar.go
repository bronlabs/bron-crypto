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

type UnitGroup interface {
	algebra.MultiplicativeGroup[*Unit]
	algebra.MultiplicativeSemiModule[*Unit, *num.Nat]
	algebra.Quotient[*Unit, *num.NatPlus, *num.Uint]
	ModulusCT() numct.Modulus
	Random(io.Reader) (*Unit, error)
	AmbientGroup() *num.ZMod
	FromUint(*num.Uint) (*Unit, error)
	FromNatCT(*numct.Nat) (*Unit, error)
}

type KnowledgeOfOrder[A modular.Arithmetic, G UnitGroup] interface {
	Arithmetic() A
	ForgetOrder() G
}

func NewUnitGroupOfUnknownOrder[X modular.Arithmetic](m *num.NatPlus) (*UZMod[X], error) {
	zMod, err := num.NewZMod(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	return &UZMod[X]{
		zMod:  zMod,
		order: cardinal.Unknown(),
	}, nil
}

func NewUnitGroup[X modular.Arithmetic](m *num.NatPlus, order cardinal.Cardinal, arith X) (*UZMod[X], error) {
	if order == nil || order.IsUnknown() {
		return nil, errs.NewValue("order must be known")
	}
	zMod, err := num.NewZMod(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	return &UZMod[X]{
		zMod:  zMod,
		order: order,
		arith: arith,
	}, nil
}

func NewUnit[X modular.Arithmetic](v *num.Uint, g *UZMod[X]) (*Unit, error) {
	if v == nil {
		return nil, errs.NewValue("v must not be nil")
	}
	if g == nil {
		return nil, errs.NewValue("g must not be nil")
	}
	if !v.Nat().Coprime(g.Modulus().Nat()) {
		return nil, errs.NewValue("v is not coprime to modulus")
	}
	if !v.Modulus().Equal(g.Modulus()) {
		return nil, errs.NewValue("v is not in the same modulus as g")
	}
	return &Unit{v: v.Clone(), g: g}, nil
}

type UZMod[X modular.Arithmetic] struct {
	zMod  *num.ZMod
	order cardinal.Cardinal
	arith X
}

func (us *UZMod[X]) Name() string {
	return fmt.Sprintf("U(Z/%sZ)*", us.Modulus().String())
}

func (us *UZMod[X]) Order() cardinal.Cardinal {
	return us.order
}

func (us *UZMod[X]) OpIdentity() *Unit {
	return us.One()
}

func (us *UZMod[X]) One() *Unit {
	return &Unit{v: us.zMod.One(), g: us}
}

func (us *UZMod[X]) Random(prng io.Reader) (*Unit, error) {
	r := us.zMod.Zero()
	var err error
	for !r.IsUnit() {
		r, err = us.zMod.Random(prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to generate random element")
		}
	}
	return &Unit{v: r, g: us}, nil
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

func (us *UZMod[X]) MultiScalarOp(scs []*num.Nat, ps []*Unit) (*Unit, error) {
	panic("implement me")
}

func (us *UZMod[X]) MultiScalarExp(scs []*num.Nat, ps []*Unit) (*Unit, error) {
	panic("implement me")
}

func (us *UZMod[X]) FromNatCT(input *numct.Nat) (*Unit, error) {
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
	return &Unit{v: elem, g: us}, nil
}

func (us *UZMod[X]) FromUint(input *num.Uint) (*Unit, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	if !us.Modulus().Equal(input.Modulus()) {
		return nil, errs.NewValue("input is not in the same modulus")
	}
	if !input.Abs().Coprime(us.Modulus().Nat()) {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	return &Unit{v: input.Clone(), g: us}, nil
}

func (us *UZMod[X]) FromBytes(input []byte) (*Unit, error) {
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
	return &Unit{v: v, g: us}, nil
}

func (us *UZMod[X]) FromCardinal(input cardinal.Cardinal) (*Unit, error) {
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
	return &Unit{v: elem, g: us}, nil
}

func (us *UZMod[X]) FromUint64(value uint64) (*Unit, error) {
	if !num.Z().FromUint64(value).Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("value is not coprime to modulus")
	}
	elem, err := us.zMod.FromCardinal(cardinal.New(value))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from uint64")
	}
	return &Unit{v: elem, g: us}, nil
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

type Unit struct {
	v *num.Uint
	g UnitGroup
}

func (u *Unit) Value() *num.Uint {
	return u.v
}

func (u *Unit) isValid(x *Unit) (*Unit, error) {
	if x == nil {
		return nil, errs.NewValue("argument is nil")
	}
	if !x.v.Modulus().Equal(u.v.Modulus()) {
		return nil, errs.NewValue("argument is not in the same modulus")
	}
	return x, nil
}

func (*Unit) ensureValid(x *Unit) *Unit {
	// TODO: fix err package
	x, err := x.isValid(x)
	if err != nil {
		panic(err)
	}
	return x
}

func (u *Unit) IsUnknownOrder() bool {
	return u.Structure().Order().IsUnknown()
}

func (u *Unit) ForgetOrder() *Unit {
	out := &Unit{v: u.v.Clone(), g: u.g}
	if u.IsUnknownOrder() {
		return out
	}
	if gRsa, ok := u.g.(RSAGroupKnownOrder); ok {
		out.g = gRsa.ForgetOrder()
		return out
	}
	if gPail, ok := u.g.(PaillierGroupKnownOrder); ok {
		out.g = gPail.ForgetOrder()
		return out
	}
	panic("cannot forget order of this group")
}

func (u *Unit) Modulus() *num.NatPlus {
	return u.v.Modulus()
}

func (u *Unit) ModulusCT() numct.Modulus {
	return u.v.ModulusCT()
}

func (u *Unit) EqualModulus(other *Unit) bool {
	_, err := u.isValid(other)
	return err == nil
}

func (u *Unit) Group() UnitGroup {
	return u.g
}

func (u *Unit) Structure() algebra.Structure[*Unit] {
	return u.g
}

func (u *Unit) Equal(other *Unit) bool {
	return u.v.Equal(other.v) && u.EqualModulus(other)
}

func (u *Unit) Clone() *Unit {
	return &Unit{v: u.v.Clone(), g: u.g}
}

func (u *Unit) Op(other *Unit) *Unit {
	return u.Mul(other)
}

func (u *Unit) Mul(other *Unit) *Unit {
	u.ensureValid(other)
	return &Unit{v: u.v.Mul(other.v), g: u.g}
}

func (u *Unit) Exp(exponent *num.Nat) *Unit {
	if exponent == nil {
		panic("exponent is nil")
	}
	var out *num.Uint
	var err error
	if u.IsUnknownOrder() {
		out = u.v.Exp(exponent)
	} else if factorisedGroup, okP := u.g.(*UZMod[*modular.OddPrimeFactors]); okP {
		outNat := new(numct.Nat)
		factorisedGroup.arith.ModExp(outNat, u.v.Nat().Value(), exponent.Value())
		out, err = factorisedGroup.AmbientStructure().FromBytes(outNat.Bytes())
		if err != nil {
			panic(err)
		}
	} else if factorisedGroup, okS := u.g.(*UZMod[*modular.OddPrimeSquareFactors]); okS {
		outNat := new(numct.Nat)
		if exponent.Value().Equal(factorisedGroup.arith.CrtModN.N.Nat()) == ct.True {
			factorisedGroup.arith.ExpToN(outNat, u.v.Nat().Value())
		} else {
			factorisedGroup.arith.ModExp(outNat, u.v.Nat().Value(), exponent.Value())
		}
		out, err = factorisedGroup.AmbientStructure().FromBytes(outNat.Bytes())
		if err != nil {
			panic(err)
		}
	} else {
		out = u.v.Exp(exponent)
	}
	return &Unit{v: out, g: u.g}
}

func (u *Unit) ExpI(exponent *num.Int) *Unit {
	if exponent == nil {
		panic("exponent is nil")
	}
	out := u.v.ExpI(exponent)
	return &Unit{v: out, g: u.g}
}

func (u *Unit) Square() *Unit {
	return &Unit{v: u.v.Square(), g: u.g}
}

func (u *Unit) TryInv() (*Unit, error) {
	return u.Inv(), nil
}

func (u *Unit) Inv() *Unit {
	out, err := u.v.TryInv()
	if err != nil {
		panic(err)
	}
	return &Unit{v: out, g: u.g}
}

func (u *Unit) TryOpInv() (*Unit, error) {
	return u.Inv(), nil
}

func (u *Unit) OpInv() *Unit {
	return u.Inv()
}

func (u *Unit) IsOpIdentity() bool {
	return u.IsOne()
}

func (u *Unit) IsOne() bool {
	return u.v.IsOne()
}

func (u *Unit) TryDiv(other *Unit) (*Unit, error) {
	return u.Div(other), nil
}

func (u *Unit) Div(other *Unit) *Unit {
	u.ensureValid(other)
	out, err := u.v.TryDiv(other.v)
	if err != nil {
		panic(err)
	}
	return &Unit{v: out, g: u.g}
}

func (u *Unit) HashCode() base.HashCode {
	return u.v.HashCode().Combine(u.v.HashCode())
}

func (u *Unit) IsTorsionFree() bool {
	panic("implement me")
}

func (u *Unit) ScalarOp(scalar *num.Nat) *Unit {
	return u.ScalarExp(scalar)
}

func (u *Unit) ScalarExp(sc *num.Nat) *Unit {
	return u.Exp(sc)
}

func (u *Unit) Cardinal() cardinal.Cardinal {
	return u.v.Cardinal()
}

func (u *Unit) Bytes() []byte {
	return u.v.Bytes()
}

func (u *Unit) String() string {
	return u.v.String()
}
