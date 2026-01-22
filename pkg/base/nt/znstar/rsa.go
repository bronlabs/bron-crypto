package znstar

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

const RSAKeyLen = base.IFCKeyLength

// SampleRSAGroup generates an RSA group with keyLen of the given bit length.
func SampleRSAGroup(keyLen uint, prng io.Reader) (*RSAGroupKnownOrder, error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng")
	}
	p, q, err := nt.GeneratePrimePair(num.NPlus(), keyLen/2, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate prime pair")
	}
	return NewRSAGroup(p, q)
}

// SampleRSAGroup generates an RSA group with random primes of the given bit length.
func NewRSAGroup(p, q *num.NatPlus) (*RSAGroupKnownOrder, error) {
	if p == nil || q == nil {
		return nil, ErrValue.WithMessage("p and q must not be nil")
	}
	if p.TrueLen() != q.TrueLen() {
		return nil, ErrValue.WithMessage("p and q must have the same length")
	}
	if p.TrueLen() < RSAKeyLen/2 {
		return nil, ErrValue.WithMessage("p and q must be at least %d bits each", RSAKeyLen/2)
	}
	if !p.IsProbablyPrime() {
		return nil, ErrValue.WithMessage("p must be prime")
	}
	if !q.IsProbablyPrime() {
		return nil, ErrValue.WithMessage("q must be prime")
	}
	n := p.Mul(q)
	zMod, err := num.NewZMod(n)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ZMod")
	}
	arith, ok := modular.NewOddPrimeFactors(p.Value(), q.Value())
	if ok == ct.False {
		return nil, ErrFailed.WithMessage("failed to create OddPrimeFactors")
	}
	return &RSAGroupKnownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.OddPrimeFactors, *RSAGroupElement[*modular.OddPrimeFactors], RSAGroupElement[*modular.OddPrimeFactors]]{
			zMod:  zMod,
			arith: arith,
			n:     n,
		},
	}, nil
}

// NewRSAGroupOfUnknownOrder creates an RSA group with unknown order from the given modulus m.
func NewRSAGroupOfUnknownOrder(m *num.NatPlus) (*RSAGroupUnknownOrder, error) {
	if m.TrueLen() < RSAKeyLen {
		return nil, ErrValue.WithMessage("modulus must be at least %d bits", RSAKeyLen)
	}
	zMod, err := num.NewZMod(m)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ZMod")
	}
	arith, ok := modular.NewSimple(zMod.Modulus().ModulusCT())
	if ok == ct.False {
		return nil, ErrFailed.WithMessage("failed to create SimpleModulus")
	}
	return &RSAGroupUnknownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *RSAGroupElement[*modular.SimpleModulus], RSAGroupElement[*modular.SimpleModulus]]{
			zMod:  zMod,
			arith: arith,
			n:     m,
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

// Equal checks if two RSA groups are equal.
func (g *RSAGroup[X]) Equal(other *RSAGroup[X]) bool {
	return g.zMod.Modulus().Equal(other.zMod.Modulus()) && g.Order().IsUnknown() == other.Order().IsUnknown()
}

// ForgetOrder converts an RSA group with known order to one with unknown order.
func (g *RSAGroup[X]) ForgetOrder() *RSAGroupUnknownOrder {
	arith, ok := modular.NewSimple(g.zMod.Modulus().ModulusCT())
	if ok == ct.False {
		panic(ErrFailed.WithMessage("failed to create SimpleModulus"))
	}
	return &RSAGroupUnknownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *RSAGroupElement[*modular.SimpleModulus], RSAGroupElement[*modular.SimpleModulus]]{
			zMod:  g.zMod,
			arith: arith,
			n:     g.n,
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
			n:     u.n,
		},
	}
}

// Structure returns the RSA group structure of the element.
func (u *RSAGroupElement[X]) Structure() algebra.Structure[*RSAGroupElement[X]] {
	return &RSAGroup[X]{
		UnitGroupTrait: UnitGroupTrait[X, *RSAGroupElement[X], RSAGroupElement[X]]{
			zMod:  u.v.Group(),
			arith: u.arith,
			n:     u.n,
		},
	}
}

// LearnOrder converts an RSA group element of unknown order to one with known order.
func (u *RSAGroupElement[X]) LearnOrder(g *RSAGroupKnownOrder) (*RSAGroupElementKnownOrder, error) {
	if g == nil {
		return nil, ErrIsNil.WithMessage("g")
	}
	if !u.v.Group().Modulus().Equal(g.zMod.Modulus()) {
		return nil, ErrValue.WithMessage("unit is not in the correct RSA group")
	}
	return &RSAGroupElementKnownOrder{
		UnitTrait: UnitTrait[*modular.OddPrimeFactors, *RSAGroupElementKnownOrder, RSAGroupElementKnownOrder]{
			v:     u.v.Clone(),
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

// ForgetOrder converts an RSA group element with known order to one with unknown order.
func (u *RSAGroupElement[X]) ForgetOrder() *RSAGroupElementUnknownOrder {
	arith, ok := modular.NewSimple(u.v.Group().Modulus().ModulusCT())
	if ok == ct.False {
		panic(ErrFailed.WithMessage("failed to create SimpleModulus"))
	}
	return &RSAGroupElementUnknownOrder{
		UnitTrait: UnitTrait[*modular.SimpleModulus, *RSAGroupElementUnknownOrder, RSAGroupElementUnknownOrder]{
			v:     u.v.Clone(),
			arith: arith,
			n:     u.n,
		},
	}
}
