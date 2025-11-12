package znstar

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func SamplePaillierGroup(factorBits uint, prng io.Reader) (*PaillierGroupKnownOrder, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	p, q, err := nt.GeneratePrimePair(num.NPlus(), factorBits, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to generate prime pair")
	}
	return NewPaillierGroup(p, q)
}

func NewPaillierGroup(p, q *num.NatPlus) (*PaillierGroupKnownOrder, error) {
	if p == nil || q == nil {
		return nil, errs.NewValue("p and q must not be nil")
	}
	if p.AnnouncedLen() != q.AnnouncedLen() {
		return nil, errs.NewValue("p and q must have the same length")
	}
	if !p.IsProbablyPrime() {
		return nil, errs.NewValue("p must be prime")
	}
	if !q.IsProbablyPrime() {
		return nil, errs.NewValue("q must be prime")
	}
	n := p.Mul(q)
	zMod, err := num.NewZMod(n.Square())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	exp, ok := modular.NewOddPrimeSquareFactors(p.Value(), q.Value())
	if ok == ct.False {
		return nil, errs.NewValue("failed to create OddPrimeFactors")
	}
	return &PaillierGroupKnownOrder{
		DenseUnitGroupTrait: DenseUnitGroupTrait[*modular.OddPrimeSquareFactors, *PaillierGroupElement[*modular.OddPrimeSquareFactors], PaillierGroupElement[*modular.OddPrimeSquareFactors]]{
			zMod:  zMod,
			arith: exp,
			n:     n,
		},
	}, nil
}

func NewPaillierGroupOfUnknownOrder(n2, n *num.NatPlus) (*PaillierGroupUnknownOrder, error) {
	if n2.AnnouncedLen() < 4096 {
		return nil, errs.NewValue("modulus must be at least 4096 bits")
	}
	if !n.Mul(n).Equal(n2) {
		return nil, errs.NewValue("n isn't sqrt of n")
	}
	zMod, err := num.NewZMod(n2)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	arith, ok := modular.NewSimple(zMod.Modulus().ModulusCT())
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create SimpleModulus")
	}

	return &PaillierGroupUnknownOrder{
		DenseUnitGroupTrait: DenseUnitGroupTrait[*modular.SimpleModulus, *PaillierGroupElement[*modular.SimpleModulus], PaillierGroupElement[*modular.SimpleModulus]]{
			zMod:  zMod,
			arith: arith,
			n:     n,
		},
	}, nil
}

type ArithmeticPaillier interface {
	*modular.SimpleModulus | *modular.OddPrimeSquareFactors
	modular.Arithmetic
}

type (
	PaillierGroupKnownOrder   = PaillierGroup[*modular.OddPrimeSquareFactors]
	PaillierGroupUnknownOrder = PaillierGroup[*modular.SimpleModulus]

	PaillierGroupKnownOrderElement   = PaillierGroupElement[*modular.OddPrimeSquareFactors]
	PaillierGroupUnknownOrderElement = PaillierGroupElement[*modular.SimpleModulus]
)

type PaillierGroup[X ArithmeticPaillier] struct {
	DenseUnitGroupTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]
}

func (g *PaillierGroup[X]) AmbientStructure() algebra.Structure[*num.Uint] {
	return g.zMod
}

func (g *PaillierGroup[X]) ScalarStructure() algebra.Structure[*num.Nat] {
	return num.N()
}

func (g *PaillierGroup[X]) Equal(other *PaillierGroup[X]) bool {
	return g.zMod.Modulus().Equal(other.zMod.Modulus())
}

func (g *PaillierGroup[X]) N() *num.NatPlus {
	return g.n
}

func (g *PaillierGroup[X]) EmbedRSA(u *RSAGroupUnknownOrderElement) (*PaillierGroupElement[X], error) {
	if u == nil {
		return nil, errs.NewIsNil("u")
	}
	if !g.n.Equal(u.Modulus()) {
		return nil, errs.NewValue("unit is not in the correct RSA group")
	}
	v, err := num.NewUintGivenModulus(u.Value().Value(), g.ModulusCT())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to embed RSA unit into Paillier unit")
	}
	return &PaillierGroupElement[X]{
		UnitTrait: UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			v:     v,
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

func (g *PaillierGroup[X]) NthResidue(u *PaillierGroupUnknownOrderElement) (*PaillierGroupElement[X], error) {
	if u == nil {
		return nil, errs.NewValue("argument must not be nil")
	}
	if !u.Modulus().Equal(g.Modulus()) {
		return nil, errs.NewValue("argument must be in the paillier group with modulus equal to the Paillier modulus")
	}
	pu, err := g.FromNatCT(u.Value().Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to lift rsaUnit to Paillier group")
	}
	lift, ok := any(g.arith).(interface {
		ExpToN(out, base *numct.Nat)
	})
	if !ok {
		return pu.Exp(g.n.Nat()), nil
	}
	var out numct.Nat
	lift.ExpToN(&out, pu.Value().Value())
	v, err := num.NewUintGivenModulus(&out, g.ModulusCT())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit from lifted value")
	}
	return &PaillierGroupElement[X]{
		UnitTrait: UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			v:     v,
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

func (pg *PaillierGroup[X]) Phi(x *numct.Int) (*PaillierGroupElement[X], error) {
	var shiftedPlaintext numct.Nat
	pg.N().ModulusCT().ModInt(&shiftedPlaintext, x)
	var out numct.Nat
	pg.ModulusCT().ModMul(&out, &shiftedPlaintext, pg.N().Value())
	out.Increment()
	return pg.FromNatCT(&out)
}

func (pg *PaillierGroup[X]) ForgetOrder() *PaillierGroupUnknownOrder {
	arith, ok := modular.NewSimple(pg.zMod.Modulus().ModulusCT())
	if ok == ct.False {
		panic(errs.NewFailed("failed to create SimpleModulus"))
	}
	return &PaillierGroupUnknownOrder{
		DenseUnitGroupTrait: DenseUnitGroupTrait[*modular.SimpleModulus, *PaillierGroupElement[*modular.SimpleModulus], PaillierGroupElement[*modular.SimpleModulus]]{
			zMod:  pg.zMod,
			arith: arith,
			n:     pg.n,
		},
	}
}

type PaillierGroupElement[X ArithmeticPaillier] struct {
	UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]
}

func (u *PaillierGroupElement[X]) Clone() *PaillierGroupElement[X] {
	return &PaillierGroupElement[X]{
		UnitTrait: UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			v:     u.v.Clone(),
			arith: u.arith,
			n:     u.n,
		},
	}
}

func (u *PaillierGroupElement[X]) Structure() algebra.Structure[*PaillierGroupElement[X]] {
	return &PaillierGroup[X]{
		DenseUnitGroupTrait: DenseUnitGroupTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			zMod:  u.v.Group(),
			arith: u.arith,
			n:     u.n,
		},
	}
}

func (u *PaillierGroupElement[X]) LearnOrder(g *PaillierGroupKnownOrder) (*PaillierGroupKnownOrderElement, error) {
	if g == nil {
		return nil, errs.NewIsNil("g")
	}
	if !u.n.Equal(g.n) {
		return nil, errs.NewValue("unit is not in the correct Paillier group")
	}
	return &PaillierGroupKnownOrderElement{
		UnitTrait: UnitTrait[*modular.OddPrimeSquareFactors, *PaillierGroupKnownOrderElement, PaillierGroupKnownOrderElement]{
			v:     u.v.Clone(),
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

func (u *PaillierGroupElement[X]) ForgetOrder() *PaillierGroupUnknownOrderElement {
	arith, ok := modular.NewSimple(u.v.Group().Modulus().ModulusCT())
	if ok == ct.False {
		panic(errs.NewFailed("failed to create SimpleModulus"))
	}
	return &PaillierGroupUnknownOrderElement{
		UnitTrait: UnitTrait[*modular.SimpleModulus, *PaillierGroupUnknownOrderElement, PaillierGroupUnknownOrderElement]{
			v:     u.v.Clone(),
			arith: arith,
			n:     u.n,
		},
	}
}
