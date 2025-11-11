package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

func NewRSAGroup(p, q *num.NatPlus) (*RSAGroupKnownOrder, error) {
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
	zMod, err := num.NewZMod(p.Mul(q))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	arith, ok := modular.NewOddPrimeFactors(p.Value(), q.Value())
	if ok == ct.False {
		return nil, errs.NewValue("failed to create OddPrimeFactors")
	}
	return &RSAGroupKnownOrder{
		DenseUnitGroupTrait: DenseUnitGroupTrait[*modular.OddPrimeFactors, *RSAGroupElement[*modular.OddPrimeFactors], RSAGroupElement[*modular.OddPrimeFactors]]{
			zMod:  zMod,
			arith: arith,
		},
	}, nil
}

func NewRSAGroupOfUnknownOrder(m *num.NatPlus) (*RSAGroupUnknownOrder, error) {
	if m.AnnouncedLen() < 2048 {
		return nil, errs.NewValue("modulus must be at least 2048 bits")
	}
	zMod, err := num.NewZMod(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	arith, ok := modular.NewSimple(zMod.Modulus().ModulusCT())
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create SimpleModulus")
	}
	return &RSAGroupUnknownOrder{
		DenseUnitGroupTrait: DenseUnitGroupTrait[*modular.SimpleModulus, *RSAGroupElement[*modular.SimpleModulus], RSAGroupElement[*modular.SimpleModulus]]{
			zMod:  zMod,
			arith: arith,
		},
	}, nil
}

type ArithmeticRSA interface {
	*modular.SimpleModulus | *modular.OddPrimeFactors
	modular.Arithmetic
}

type (
	RSAGroupKnownOrder   = RSAGroup[*modular.OddPrimeFactors]
	RSAGroupUnknownOrder = RSAGroup[*modular.SimpleModulus]

	RSAGroupKnownOrderElement   = RSAGroupElement[*modular.OddPrimeFactors]
	RSAGroupUnknownOrderElement = RSAGroupElement[*modular.SimpleModulus]
)

type RSAGroup[X ArithmeticRSA] struct {
	DenseUnitGroupTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]
}

func (g *RSAGroup[X]) AmbientStructure() algebra.Structure[*num.Uint] {
	return g.zMod
}

func (g *RSAGroup[X]) ScalarStructure() algebra.Structure[*num.Nat] {
	return num.N()
}

func (g *RSAGroup[X]) Equal(other *RSAGroup[X]) bool {
	return g.zMod.Modulus().Equal(other.zMod.Modulus()) && g.Order().Equal(other.Order())
}

func (g *RSAGroup[X]) ForgetOrder() *RSAGroupUnknownOrder {
	arith, ok := modular.NewSimple(g.zMod.Modulus().ModulusCT())
	if ok == ct.False {
		panic(errs.NewFailed("failed to create SimpleModulus"))
	}
	return &RSAGroupUnknownOrder{
		DenseUnitGroupTrait: DenseUnitGroupTrait[*modular.SimpleModulus, *RSAGroupElement[*modular.SimpleModulus], RSAGroupElement[*modular.SimpleModulus]]{
			zMod:  g.zMod,
			arith: arith,
		},
	}
}

type RSAGroupElement[X ArithmeticRSA] struct {
	UnitTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]
}

func (u *RSAGroupElement[X]) Clone() *RSAGroupElement[X] {
	return &RSAGroupElement[X]{
		UnitTrait: UnitTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]{
			v:     u.v.Clone(),
			arith: u.arith,
		},
	}
}

func (u *RSAGroupElement[X]) Structure() algebra.Structure[*RSAGroupElement[X]] {
	return &RSAGroup[X]{
		DenseUnitGroupTrait: DenseUnitGroupTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]{
			zMod:  u.v.Group(),
			arith: u.arith,
		},
	}
}

func (u *RSAGroupElement[X]) LearnOrder(g *RSAGroupKnownOrder) (*RSAGroupKnownOrderElement, error) {
	if g == nil {
		return nil, errs.NewIsNil("g")
	}
	if !u.v.Group().Modulus().Equal(g.zMod.Modulus()) {
		return nil, errs.NewValue("unit is not in the correct RSA group")
	}
	return &RSAGroupKnownOrderElement{
		UnitTrait: UnitTrait[*modular.OddPrimeFactors, *RSAGroupKnownOrderElement, RSAGroupKnownOrderElement]{
			v:     u.v.Clone(),
			arith: g.arith,
		},
	}, nil
}

func (u *RSAGroupElement[X]) ForgetOrder() *RSAGroupUnknownOrderElement {
	arith, ok := modular.NewSimple(u.v.Group().Modulus().ModulusCT())
	if ok == ct.False {
		panic(errs.NewFailed("failed to create SimpleModulus"))
	}
	return &RSAGroupUnknownOrderElement{
		UnitTrait: UnitTrait[*modular.SimpleModulus, *RSAGroupUnknownOrderElement, RSAGroupUnknownOrderElement]{
			v:     u.v.Clone(),
			arith: arith,
		},
	}
}
