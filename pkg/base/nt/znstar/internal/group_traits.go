package internal

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type UnitGroupTrait[G interface {
	Order() cardinal.Cardinal
}, U Unit[U], W UnitPtrConstraint[G, U, WT], WT any] struct {
	BaseRing *num.ZMod
	Group    G
}

func (us *UnitGroupTrait[G, U, W, WT]) Name() string {
	return fmt.Sprintf("U(Z/%sZ)*", us.Modulus().String())
}

func (us *UnitGroupTrait[G, U, W, WT]) Order() cardinal.Cardinal {
	return us.Group.Order()
}

func (us *UnitGroupTrait[G, U, W, WT]) OpIdentity() W {
	return us.One()
}

func (us *UnitGroupTrait[G, U, W, WT]) One() W {
	var out WT
	W(&out).setValue(us.BaseRing.One().Value())
	W(&out).setModulus(us.ModulusCT())
	W(&out).setGroup(us.Group)
	return &out
}

func (us *UnitGroupTrait[G, U, W, WT]) Random(prng io.Reader) (W, error) {
	r := us.BaseRing.Zero()
	var err error
	for !r.IsUnit() {
		r, err = us.BaseRing.Random(prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to generate random element")
		}
	}
	var out WT
	W(&out).setValue(r.Value())
	W(&out).setModulus(us.ModulusCT())
	W(&out).setGroup(us.Group)
	return &out, nil
}

func (us *UnitGroupTrait[G, U, W, WT]) Modulus() *num.NatPlus {
	return us.BaseRing.Modulus()
}

func (us *UnitGroupTrait[G, U, W, WT]) ModulusCT() numct.Modulus {
	return us.BaseRing.Modulus().ModulusCT()
}

func (us *UnitGroupTrait[G, U, W, WT]) ElementSize() int {
	return us.BaseRing.ElementSize()
}

func (us *UnitGroupTrait[G, U, W, WT]) MultiScalarOp(scs []*num.Nat, ps []W) (W, error) {
	panic("implement me")
}

func (us *UnitGroupTrait[G, U, W, WT]) MultiScalarExp(scs []*num.Nat, ps []W) (W, error) {
	panic("implement me")
}

func (us *UnitGroupTrait[G, U, W, WT]) FromNatCT(input *numct.Nat) (W, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	if input.Coprime(us.ModulusCT().Nat()) == ct.False {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	elem, err := us.BaseRing.FromNatCT(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from nat")
	}
	var out WT
	W(&out).setValue(elem.Value())
	W(&out).setModulus(us.ModulusCT())
	W(&out).setGroup(us.Group)
	return &out, nil
}

func (us *UnitGroupTrait[G, U, W, WT]) FromUint(input *num.Uint) (W, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	if !us.Modulus().Equal(input.Modulus()) {
		return nil, errs.NewValue("input is not in the same modulus")
	}
	if !input.Abs().Coprime(us.Modulus().Nat()) {
		return nil, errs.NewValue("input is not coprime to modulus")
	}
	var out WT
	W(&out).setValue(input.Clone().Value())
	W(&out).setModulus(us.ModulusCT())
	W(&out).setGroup(us.Group)
	return &out, nil
}

func (us *UnitGroupTrait[G, U, W, WT]) FromBytes(input []byte) (W, error) {
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
	v, err := us.BaseRing.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit from bytes")
	}
	var out WT
	W(&out).setValue(v.Value())
	W(&out).setModulus(us.ModulusCT())
	W(&out).setGroup(us.Group)
	return &out, nil
}

func (us *UnitGroupTrait[G, U, W, WT]) FromCardinal(input cardinal.Cardinal) (W, error) {
	elem, err := us.BaseRing.FromCardinal(input)
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
	var out WT
	W(&out).setValue(elem.Value())
	W(&out).setModulus(us.ModulusCT())
	W(&out).setGroup(us.Group)
	return &out, nil
}

func (us *UnitGroupTrait[G, U, W, WT]) FromUint64(value uint64) (W, error) {
	if !num.Z().FromUint64(value).Coprime(us.Modulus().Lift()) {
		return nil, errs.NewValue("value is not coprime to modulus")
	}
	elem, err := us.BaseRing.FromCardinal(cardinal.New(value))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from uint64")
	}
	var out WT
	W(&out).setValue(elem.Value())
	W(&out).setModulus(us.ModulusCT())
	W(&out).setGroup(us.Group)
	return &out, nil
}

func (us *UnitGroupTrait[G, U, W, WT]) ScalarStructure() algebra.Structure[*num.Nat] {
	return num.N()
}

func (us *UnitGroupTrait[G, U, W, WT]) AmbientStructure() algebra.Structure[*num.Uint] {
	return us.BaseRing
}

func (us *UnitGroupTrait[G, U, W, WT]) AmbientGroup() *num.ZMod {
	return us.BaseRing
}
