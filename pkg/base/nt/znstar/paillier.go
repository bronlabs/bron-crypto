package znstar

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

const PaillierKeyLen = base.IFCKeyLength

// SamplePaillierGroup generates a Paillier group with modulus of given bitlen.
func SamplePaillierGroup(keyLen uint, prng io.Reader) (*PaillierGroupKnownOrder, error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng")
	}
	p, q, err := nt.GeneratePrimePair(num.NPlus(), keyLen/2, prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to generate prime pair")
	}
	return NewPaillierGroup(p, q)
}

// NewPaillierGroup creates a Paillier group with known order from the given primes p and q.
func NewPaillierGroup(p, q *num.NatPlus) (*PaillierGroupKnownOrder, error) {
	if p == nil || q == nil {
		return nil, ErrValue.WithMessage("p and q must not be nil")
	}
	if p.TrueLen() != q.TrueLen() {
		return nil, ErrValue.WithMessage("p and q must have the same length")
	}
	if p.TrueLen() < PaillierKeyLen/2 {
		return nil, ErrValue.WithMessage("p and q must be at least %d bits each", PaillierKeyLen/2)
	}
	if !p.IsProbablyPrime() {
		return nil, ErrValue.WithMessage("p must be prime")
	}
	if !q.IsProbablyPrime() {
		return nil, ErrValue.WithMessage("q must be prime")
	}
	n := p.Mul(q)
	zMod, err := num.NewZMod(n.Square())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create ZMod")
	}
	exp, ok := modular.NewOddPrimeSquareFactors(p.Value(), q.Value())
	if ok == ct.False {
		return nil, ErrFailed.WithMessage("failed to create OddPrimeFactors")
	}
	return &PaillierGroupKnownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.OddPrimeSquareFactors, *PaillierGroupElement[*modular.OddPrimeSquareFactors], PaillierGroupElement[*modular.OddPrimeSquareFactors]]{
			zMod:  zMod,
			arith: exp,
			n:     n,
		},
	}, nil
}

// NewPaillierGroupOfUnknownOrder creates a Paillier group with unknown order from the given modulus n^2 and n.
func NewPaillierGroupOfUnknownOrder(n2, n *num.NatPlus) (*PaillierGroupUnknownOrder, error) {
	if n.TrueLen() < PaillierKeyLen-1 {
		return nil, ErrValue.WithMessage("modulus n must be at least %d bits", PaillierKeyLen-1)
	}
	if !n.Mul(n).Equal(n2) {
		return nil, ErrValue.WithMessage("n isn't sqrt of n")
	}
	zMod, err := num.NewZMod(n2)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create ZMod")
	}
	arith, ok := modular.NewSimple(zMod.Modulus().ModulusCT())
	if ok == ct.False {
		return nil, ErrFailed.WithMessage("failed to create SimpleModulus")
	}

	return &PaillierGroupUnknownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *PaillierGroupElement[*modular.SimpleModulus], PaillierGroupElement[*modular.SimpleModulus]]{
			zMod:  zMod,
			arith: arith,
			n:     n,
		},
	}, nil
}

// ArithmeticPaillier defines the supported arithmetic types for Paillier groups.
type ArithmeticPaillier interface {
	*modular.SimpleModulus | *modular.OddPrimeSquareFactors
	modular.Arithmetic
}

type (
	// PaillierGroupKnownOrder defines a Paillier group with known order.
	PaillierGroupKnownOrder = PaillierGroup[*modular.OddPrimeSquareFactors]
	// PaillierGroupUnknownOrder defines a Paillier group with unknown order.
	PaillierGroupUnknownOrder = PaillierGroup[*modular.SimpleModulus]

	// PaillierGroupElementKnownOrder defines a Paillier group element with known order.
	PaillierGroupElementKnownOrder = PaillierGroupElement[*modular.OddPrimeSquareFactors]
	// PaillierGroupElementUnknownOrder defines a Paillier group element with unknown order.
	PaillierGroupElementUnknownOrder = PaillierGroupElement[*modular.SimpleModulus]
)

// PaillierGroup defines a Paillier group structure.
// X is the arithmetic type used for the group and determines whether the group has known or unknown order.
type PaillierGroup[X ArithmeticPaillier] struct {
	UnitGroupTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]
}

// Equal checks if two Paillier groups are equal.
func (g *PaillierGroup[X]) Equal(other *PaillierGroup[X]) bool {
	return g.zMod.Modulus().Equal(other.zMod.Modulus()) && g.Order().IsUnknown() == other.Order().IsUnknown()
}

// N returns the Paillier modulus n.
func (g *PaillierGroup[X]) N() *num.NatPlus {
	return g.n
}

// EmbedRSA embeds an RSA unit into the Paillier group as a Paillier unit.
func (g *PaillierGroup[X]) EmbedRSA(u *RSAGroupElementUnknownOrder) (*PaillierGroupElement[X], error) {
	if u == nil {
		return nil, ErrIsNil.WithMessage("u")
	}
	if !g.n.Equal(u.Modulus()) {
		return nil, ErrValue.WithMessage("unit is not in the correct RSA group")
	}
	v, err := num.NewUintGivenModulus(u.Value().Value(), g.ModulusCT())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to embed RSA unit into Paillier unit")
	}
	return &PaillierGroupElement[X]{
		UnitTrait: UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			v:     v,
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

// NthResidue computes the n-th residue of a Paillier group element of unknown order.
func (g *PaillierGroup[X]) NthResidue(u *PaillierGroupElementUnknownOrder) (*PaillierGroupElement[X], error) {
	if u == nil {
		return nil, ErrIsNil.WithMessage("argument must not be nil")
	}
	if !u.Modulus().Equal(g.Modulus()) {
		return nil, ErrValue.WithMessage("argument must be in the paillier group with modulus equal to the Paillier modulus")
	}
	pu, err := g.FromNatCT(u.Value().Value())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to lift rsaUnit to Paillier group")
	}
	lift, ok := any(g.arith).(interface {
		ExpToN(out, base *numct.Nat) //nolint:revive // base shadows an import but here it's clearer.
	})
	if !ok {
		return pu.Exp(g.n.Nat()), nil
	}
	var out numct.Nat
	lift.ExpToN(&out, pu.Value().Value())
	v, err := num.NewUintGivenModulus(&out, g.ModulusCT())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create unit from lifted value")
	}
	return &PaillierGroupElement[X]{
		UnitTrait: UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			v:     v,
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

// Representative computes the representative of a plaintext in the Paillier group. It is equivalent to computing (1 + m*n) mod n^2.
func (g *PaillierGroup[X]) Representative(plaintext *numct.Int) (*PaillierGroupElement[X], error) {
	if g.N().ModulusCT().IsInRangeSymmetric(plaintext) == ct.False {
		return nil, ErrValue.WithMessage("plaintext is out of range: |plaintext| >= n/2")
	}
	var shiftedPlaintext numct.Nat
	g.N().ModulusCT().ModI(&shiftedPlaintext, plaintext)
	var out numct.Nat
	g.ModulusCT().ModMul(&out, &shiftedPlaintext, g.N().Value())
	out.Increment()
	return g.FromNatCT(&out)
}

// ForgetOrder returns a Paillier group with unknown order.
func (g *PaillierGroup[X]) ForgetOrder() *PaillierGroupUnknownOrder {
	arith, ok := modular.NewSimple(g.zMod.Modulus().ModulusCT())
	if ok == ct.False {
		panic(ErrFailed.WithMessage("failed to create SimpleModulus"))
	}
	return &PaillierGroupUnknownOrder{
		UnitGroupTrait: UnitGroupTrait[*modular.SimpleModulus, *PaillierGroupElement[*modular.SimpleModulus], PaillierGroupElement[*modular.SimpleModulus]]{
			zMod:  g.zMod,
			arith: arith,
			n:     g.n,
		},
	}
}

// PaillierGroupElement defines a Paillier group element.
// X is the arithmetic type used for the group element and determines whether the group has known or unknown order.
type PaillierGroupElement[X ArithmeticPaillier] struct {
	UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]
}

// Clone creates a copy of the Paillier group element.
func (u *PaillierGroupElement[X]) Clone() *PaillierGroupElement[X] {
	return &PaillierGroupElement[X]{
		UnitTrait: UnitTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			v:     u.v.Clone(),
			arith: u.arith,
			n:     u.n,
		},
	}
}

// Structure returns the Paillier group structure of the element.
func (u *PaillierGroupElement[X]) Structure() algebra.Structure[*PaillierGroupElement[X]] {
	return &PaillierGroup[X]{
		UnitGroupTrait: UnitGroupTrait[X, *PaillierGroupElement[X], PaillierGroupElement[X]]{
			zMod:  u.v.Group(),
			arith: u.arith,
			n:     u.n,
		},
	}
}

// LearnOrder converts a Paillier group element of unknown order to one with known order.
func (u *PaillierGroupElement[X]) LearnOrder(g *PaillierGroupKnownOrder) (*PaillierGroupElementKnownOrder, error) {
	if g == nil {
		return nil, ErrIsNil.WithMessage("g")
	}
	if !u.n.Equal(g.n) {
		return nil, ErrValue.WithMessage("unit is not in the correct Paillier group")
	}
	return &PaillierGroupElementKnownOrder{
		UnitTrait: UnitTrait[*modular.OddPrimeSquareFactors, *PaillierGroupElementKnownOrder, PaillierGroupElementKnownOrder]{
			v:     u.v.Clone(),
			arith: g.arith,
			n:     g.n,
		},
	}, nil
}

// ForgetOrder converts a Paillier group element with known order to one with unknown order.
func (u *PaillierGroupElement[X]) ForgetOrder() *PaillierGroupElementUnknownOrder {
	arith, ok := modular.NewSimple(u.v.Group().Modulus().ModulusCT())
	if ok == ct.False {
		panic(ErrFailed.WithMessage("failed to create SimpleModulus"))
	}
	return &PaillierGroupElementUnknownOrder{
		UnitTrait: UnitTrait[*modular.SimpleModulus, *PaillierGroupElementUnknownOrder, PaillierGroupElementUnknownOrder]{
			v:     u.v.Clone(),
			arith: arith,
			n:     u.n,
		},
	}
}
