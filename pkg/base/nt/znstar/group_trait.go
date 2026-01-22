package znstar

import (
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/errs-go/errs"
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

type UnitGroupTrait[A modular.Arithmetic, W unitWrapperPtrConstraint[A, WT], WT any] struct {
	zMod  *num.ZMod
	arith A
	n     *num.NatPlus
}

func (g *UnitGroupTrait[A, W, WT]) Name() string {
	return fmt.Sprintf("U(Z/%sZ)*", g.Modulus().String())
}

func (g *UnitGroupTrait[A, W, WT]) Order() cardinal.Cardinal {
	return g.arith.MultiplicativeOrder()
}

func (g *UnitGroupTrait[A, W, WT]) OpIdentity() W {
	return g.One()
}

func (g *UnitGroupTrait[A, W, WT]) One() W {
	var u WT
	W(&u).set(g.zMod.One(), g.arith, g.n)
	return W(&u)
}

func (g *UnitGroupTrait[A, W, WT]) Random(prng io.Reader) (W, error) {
	for {
		r, err := g.zMod.Random(prng)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		var u WT
		W(&u).set(r, g.arith, g.n)
		if W(&u).Value().Lift().Coprime(g.Modulus().Lift()) {
			return W(&u), nil
		}
	}
}

func (g *UnitGroupTrait[A, W, WT]) Hash(input []byte) (W, error) {
	xof, err := blake2b.NewXOF(uint32(g.WideElementSize()), nil)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if _, err := xof.Write(input); err != nil {
		return nil, errs.Wrap(err)
	}
	digest := make([]byte, g.WideElementSize())
	var x, v numct.Nat
	for {
		if _, err = io.ReadFull(xof, digest); err != nil {
			return nil, errs.Wrap(err)
		}
		if ok := x.SetBytes(digest); ok == ct.False {
			return nil, ErrFailed.WithMessage("failed to interpret hash digest as Nat")
		}
		// Perform modular reduction using the modulus from n
		g.zMod.ModulusCT().Mod(&v, &x)

		vNat, err := num.N().FromNatCT(&v)
		if err != nil {
			return nil, errs.Wrap(err)
		}

		if g.zMod.Modulus().Nat().Coprime(vNat) {
			uv, err := g.zMod.FromNat(vNat)
			if err != nil {
				return nil, errs.Wrap(err)
			}
			var zn WT
			W(&zn).set(uv, g.arith, g.n)
			return W(&zn), nil
		}
	}
}

func (g *UnitGroupTrait[A, W, WT]) Modulus() *num.NatPlus {
	return g.zMod.Modulus()
}

func (g *UnitGroupTrait[A, W, WT]) ModulusCT() *numct.Modulus {
	return g.zMod.Modulus().ModulusCT()
}

func (g *UnitGroupTrait[A, W, WT]) ElementSize() int {
	return g.zMod.ElementSize()
}

func (g *UnitGroupTrait[A, W, WT]) WideElementSize() int {
	return g.zMod.WideElementSize()
}

func (g *UnitGroupTrait[A, W, WT]) FromNatCT(input *numct.Nat) (W, error) {
	if input == nil {
		return nil, ErrIsNil.WithMessage("input must not be nil")
	}
	elem, err := g.zMod.FromNatCT(input)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create element from nat")
	}
	var out WT
	W(&out).set(elem, g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}
	return W(&out), nil
}

func (g *UnitGroupTrait[A, W, WT]) FromUint(input *num.Uint) (W, error) {
	if input == nil {
		return nil, ErrIsNil.WithMessage("input must not be nil")
	}
	if !g.Modulus().Equal(input.Modulus()) {
		return nil, ErrValue.WithMessage("input is not in the same modulus")
	}
	var out WT
	W(&out).set(input.Clone(), g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}
	return W(&out), nil
}

func (g *UnitGroupTrait[A, W, WT]) FromBytes(input []byte) (W, error) {
	if len(input) == 0 {
		return nil, ErrIsNil.WithMessage("input must not be empty")
	}
	v, err := g.zMod.FromBytes(input)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create unit from bytes")
	}
	var out WT
	W(&out).set(v, g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}
	return W(&out), nil
}

func (g *UnitGroupTrait[A, W, WT]) FromCardinal(input cardinal.Cardinal) (W, error) {
	elem, err := g.zMod.FromCardinal(input)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create element from cardinal")
	}
	var out WT
	W(&out).set(elem, g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}
	return W(&out), nil
}

func (g *UnitGroupTrait[A, W, WT]) FromUint64(input uint64) (W, error) {
	elem, err := g.zMod.FromCardinal(cardinal.New(input))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create element from uint64")
	}
	var out WT
	W(&out).set(elem, g.arith, g.n)
	if !W(&out).Value().Lift().Coprime(g.Modulus().Lift()) {
		return nil, ErrValue.WithMessage("input is not a unit")
	}

	return W(&out), nil
}

func (g *UnitGroupTrait[A, W, WT]) AmbientGroup() *num.ZMod {
	return g.zMod
}

func (g *UnitGroupTrait[A, W, WT]) AmbientStructure() algebra.Structure[*num.Uint] {
	return g.zMod
}

func (*UnitGroupTrait[A, W, WT]) ScalarStructure() algebra.Structure[*num.Int] {
	return num.Z()
}

func (g *UnitGroupTrait[A, W, WT]) Arithmetic() modular.Arithmetic {
	return g.arith
}
