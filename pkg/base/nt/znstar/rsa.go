package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

// SampleRSAGroup generates an RSA group with random primes of the given bit length.
func NewRSAGroup(p, q *num.NatPlus) (*RSAGroupKnownOrder, error) {
	if p == nil || q == nil {
		return nil, errs.NewValue("p and q must not be nil")
	}
	if p.AnnouncedLen() != q.AnnouncedLen() {
		return nil, errs.NewValue("p and q must have the same length")
	}
	if p.AnnouncedLen() < 1024 {
		return nil, errs.NewValue("p and q must be at least 1024 bits each")
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
		UnitGroupTrait: UnitGroupTrait[*modular.OddPrimeFactors, *RSAGroupElement[*modular.OddPrimeFactors], RSAGroupElement[*modular.OddPrimeFactors]]{
			zMod:  zMod,
			arith: arith,
		},
	}, nil
}

// NewRSAGroupOfUnknownOrder creates an RSA group with unknown order from the given modulus m.
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
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *RSAGroupElement[*modular.SimpleModulus], RSAGroupElement[*modular.SimpleModulus]]{
			zMod:  zMod,
			arith: arith,
		},
	}, nil
}

// ArithmeticRSA defines the arithmetic types used in RSA groups.
type ArithmeticRSA interface {
	*modular.SimpleModulus | *modular.OddPrimeFactors
	modular.Arithmetic
}

type (
	// RSAGroupKnownOrder defines an RSA group with known order.
	RSAGroupKnownOrder = RSAGroup[*modular.OddPrimeFactors]
	// RSAGroupUnknownOrder defines an RSA group with unknown order.
	RSAGroupUnknownOrder = RSAGroup[*modular.SimpleModulus]

	// RSAGroupElementKnownOrder defines an RSA group element with known order.
	RSAGroupElementKnownOrder = RSAGroupElement[*modular.OddPrimeFactors]
	// RSAGroupElementUnknownOrder defines an RSA group element with unknown order.
	RSAGroupElementUnknownOrder = RSAGroupElement[*modular.SimpleModulus]
)

// RSAGroup defines an RSA unit group.
// X is the arithmetic type used for the group and determines whether the group has known or unknown order.
type RSAGroup[X ArithmeticRSA] struct {
	UnitGroupTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]
}

// AmbientStructure returns the ambient structure of the RSA group ie. Z\\{n}Z.
func (g *RSAGroup[X]) AmbientStructure() algebra.Structure[*num.Uint] {
	return g.zMod
}

// ScalarStructure returns the scalar structure of the RSA's induced semi module ie. N.
func (g *RSAGroup[X]) ScalarStructure() algebra.Structure[*num.Nat] {
	return num.N()
}

// Equal checks if two RSA groups are equal.
func (g *RSAGroup[X]) Equal(other *RSAGroup[X]) bool {
	return g.zMod.Modulus().Equal(other.zMod.Modulus()) && g.Order().Equal(other.Order())
}

// ForgetOrder converts an RSA group with known order to one with unknown order.
func (g *RSAGroup[X]) ForgetOrder() *RSAGroupUnknownOrder {
	arith, ok := modular.NewSimple(g.zMod.Modulus().ModulusCT())
	if ok == ct.False {
		panic(errs.NewFailed("failed to create SimpleModulus"))
	}
	return &RSAGroupUnknownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *RSAGroupElement[*modular.SimpleModulus], RSAGroupElement[*modular.SimpleModulus]]{
			zMod:  g.zMod,
			arith: arith,
		},
	}
}

// RSAGroupElement defines an RSA group element.
// X is the arithmetic type used for the group element and determines whether the group has known or unknown order.
type RSAGroupElement[X ArithmeticRSA] struct {
	UnitTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]
}

// Clone creates a copy of the RSA group element.
func (u *RSAGroupElement[X]) Clone() *RSAGroupElement[X] {
	return &RSAGroupElement[X]{
		UnitTrait: UnitTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]{
			v:     u.v.Clone(),
			arith: u.arith,
		},
	}
}

// Structure returns the RSA group structure of the element.
func (u *RSAGroupElement[X]) Structure() algebra.Structure[*RSAGroupElement[X]] {
	return &RSAGroup[X]{
		UnitGroupTrait: UnitGroupTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]{
			zMod:  u.v.Group(),
			arith: u.arith,
		},
	}
}

// LearnOrder converts an RSA group element of unknown order to one with known order.
func (u *RSAGroupElement[X]) LearnOrder(g *RSAGroupKnownOrder) (*RSAGroupElementKnownOrder, error) {
	if g == nil {
		return nil, errs.NewIsNil("g")
	}
	if !u.v.Group().Modulus().Equal(g.zMod.Modulus()) {
		return nil, errs.NewValue("unit is not in the correct RSA group")
	}
	return &RSAGroupElementKnownOrder{
		UnitTrait: UnitTrait[*modular.OddPrimeFactors, *RSAGroupElementKnownOrder, RSAGroupElementKnownOrder]{
			v:     u.v.Clone(),
			arith: g.arith,
		},
	}, nil
}

// ForgetOrder converts an RSA group element with known order to one with unknown order.
func (u *RSAGroupElement[X]) ForgetOrder() *RSAGroupElementUnknownOrder {
	arith, ok := modular.NewSimple(u.v.Group().Modulus().ModulusCT())
	if ok == ct.False {
		panic(errs.NewFailed("failed to create SimpleModulus"))
	}
	return &RSAGroupElementUnknownOrder{
		UnitTrait: UnitTrait[*modular.SimpleModulus, *RSAGroupElementUnknownOrder, RSAGroupElementUnknownOrder]{
			v:     u.v.Clone(),
			arith: arith,
		},
	}
}
