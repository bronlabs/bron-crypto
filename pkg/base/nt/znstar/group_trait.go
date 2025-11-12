package znstar

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type unitWrapper[A modular.Arithmetic] interface {
	set(*num.Uint, A, *num.NatPlus)
	Arithmetic() A
	Modulus() *num.NatPlus
	IsUnknownOrder() bool
	base.Transparent[*num.Uint]
}

type unitWrapperPtrConstraint[A modular.Arithmetic, WT any] interface {
	*WT
	unitWrapper[A]
}

type DenseUnitGroupTrait[A modular.Arithmetic, W unitWrapperPtrConstraint[A, WT], WT any] struct {
	zMod  *num.ZMod
	arith A
	n     *num.NatPlus
}

func (g *DenseUnitGroupTrait[A, W, WT]) Name() string {
	return fmt.Sprintf("U(Z/%sZ)*", g.Modulus().String())
}

func (g *DenseUnitGroupTrait[A, W, WT]) Order() cardinal.Cardinal {
	return g.arith.MultiplicativeOrder()
}

func (g *DenseUnitGroupTrait[A, W, WT]) OpIdentity() W {
	return g.One()
}

func (g *DenseUnitGroupTrait[A, W, WT]) One() W {
	var u WT
	W(&u).set(g.zMod.One(), g.arith, g.n)
	return W(&u)
}

func (g *DenseUnitGroupTrait[A, W, WT]) Random(prng io.Reader) (W, error) {
	r, err := g.zMod.Random(prng)
	if err != nil {
		return nil, err
	}
	var u WT
	W(&u).set(r, g.arith, g.n)
	return W(&u), nil
}

func (g *DenseUnitGroupTrait[A, W, WT]) Hash(input []byte) (W, error) {
	panic("not implemented")
}

func (g *DenseUnitGroupTrait[A, W, WT]) Modulus() *num.NatPlus {
	return g.zMod.Modulus()
}

func (g *DenseUnitGroupTrait[A, W, WT]) ModulusCT() numct.Modulus {
	return g.zMod.Modulus().ModulusCT()
}

func (g *DenseUnitGroupTrait[A, W, WT]) ElementSize() int {
	return g.zMod.ElementSize()
}

func (dus *DenseUnitGroupTrait[A, W, WT]) MultiScalarOp(scs []*num.Nat, ps []W) (W, error) {
	panic("implement me")
}

func (dus *DenseUnitGroupTrait[A, W, WT]) MultiScalarExp(scs []*num.Nat, ps []W) (W, error) {
	panic("implement me")
}

func (g *DenseUnitGroupTrait[A, W, WT]) FromNatCT(input *numct.Nat) (W, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	elem, err := g.zMod.FromNatCT(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from nat")
	}
	var out WT
	W(&out).set(elem, g.arith, g.n)
	return W(&out), nil
}

func (g *DenseUnitGroupTrait[A, W, WT]) FromUint(input *num.Uint) (W, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	if !g.Modulus().Equal(input.Modulus()) {
		return nil, errs.NewValue("input is not in the same modulus")
	}
	var out WT
	W(&out).set(input.Clone(), g.arith, g.n)
	return W(&out), nil
}

func (g *DenseUnitGroupTrait[A, W, WT]) FromBytes(input []byte) (W, error) {
	if len(input) == 0 {
		return nil, errs.NewValue("input must not be empty")
	}
	v, err := g.zMod.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit from bytes")
	}
	var out WT
	W(&out).set(v, g.arith, g.n)
	return W(&out), nil
}

func (g *DenseUnitGroupTrait[A, W, WT]) FromCardinal(input cardinal.Cardinal) (W, error) {
	elem, err := g.zMod.FromCardinal(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from cardinal")
	}
	var out WT
	W(&out).set(elem, g.arith, g.n)
	return W(&out), nil
}

func (g *DenseUnitGroupTrait[A, W, WT]) FromUint64(input uint64) (W, error) {
	elem, err := g.zMod.FromCardinal(cardinal.New(input))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create element from uint64")
	}
	var out WT
	W(&out).set(elem, g.arith, g.n)
	return W(&out), nil
}

func (g *DenseUnitGroupTrait[A, W, WT]) AmbientGroup() *num.ZMod {
	return g.zMod
}

func (g *DenseUnitGroupTrait[A, W, WT]) Arithmetic() modular.Arithmetic {
	return g.arith
}

type UnitGroupTrait[A modular.Arithmetic, W unitWrapperPtrConstraint[A, WT], WT any] struct {
	DenseUnitGroupTrait[A, W, WT]
}

func (g *UnitGroupTrait[A, W, WT]) Random(prng io.Reader) (W, error) {
	for {
		u, err := g.DenseUnitGroupTrait.Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not sample random unit")
		}
		if u.Value().Lift().Coprime(g.Modulus().Lift()) {
			return u, nil
		}
	}
}

func (g *UnitGroupTrait[A, W, WT]) FromNatCT(input *numct.Nat) (W, error) {
	out, err := g.DenseUnitGroupTrait.FromNatCT(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert from natct")
	}
	if !out.Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, errs.NewValue("input is not a unit")
	}
	return out, nil
}

func (g *UnitGroupTrait[A, W, WT]) FromUint(input *num.Uint) (W, error) {
	out, err := g.DenseUnitGroupTrait.FromUint(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert from uint")
	}
	if !out.Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, errs.NewValue("input is not a unit")
	}
	return out, nil
}

func (g *UnitGroupTrait[A, W, WT]) FromBytes(input []byte) (W, error) {
	out, err := g.DenseUnitGroupTrait.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert from bytes")
	}
	if !out.Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, errs.NewValue("input is not a unit")
	}
	return out, nil
}

func (g *UnitGroupTrait[A, W, WT]) FromCardinal(input cardinal.Cardinal) (W, error) {
	out, err := g.DenseUnitGroupTrait.FromCardinal(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert from cardinal")
	}
	if !out.Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, errs.NewValue("input is not a unit")
	}
	return out, nil
}

func (g *UnitGroupTrait[A, W, WT]) FromUint64(input uint64) (W, error) {
	out, err := g.DenseUnitGroupTrait.FromUint64(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert from uint64")
	}
	if !out.Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, errs.NewValue("input is not a unit")
	}
	return out, nil
}
