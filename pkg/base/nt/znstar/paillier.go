package znstar

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func PaillierGroupsAreEqual[G PaillierGroup](a, b G) bool {
	return (a.N().Value().Equal(b.N().Value()))&a.ModulusCT().Nat().Equal(b.ModulusCT().Nat()) == ct.True
}

type PaillierGroup interface {
	algebra.FiniteStructure[Unit]
	UnitGroup
	N() *num.NatPlus
	EmbedRSA(Unit) (Unit, error)
	LiftToNthResidues(rsaUnit Unit) (Unit, error)
	Phi(*numct.Int) (Unit, error)
}

type PaillierGroupKnownOrder interface {
	PaillierGroup
	KnowledgeOfOrder[*modular.OddPrimeSquareFactors, PaillierGroup]
}

func SamplePaillierGroup(factorBits uint, prng io.Reader) (PaillierGroupKnownOrder, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	p, q, err := nt.GeneratePrimePair(num.NPlus(), factorBits, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to generate prime pair")
	}
	return NewPaillierGroup(p, q)
}

func NewPaillierGroup(p, q *num.NatPlus) (PaillierGroupKnownOrder, error) {
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
	return &paillierGroupKnownOrder{
		UZMod: UZMod[*modular.OddPrimeSquareFactors]{
			zMod:  zMod,
			arith: exp,
		},
		n: n,
	}, nil
}

func NewPaillierGroupOfUnknownOrder(n2, n *num.NatPlus) (PaillierGroup, error) {
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

	return &paillierGroup{
		UZMod: UZMod[*modular.SimpleModulus]{
			zMod:  zMod,
			arith: arith,
		},
		n: n,
	}, nil
}

type paillierGroup struct {
	UZMod[*modular.SimpleModulus]

	n *num.NatPlus
}

func (pg *paillierGroup) N() *num.NatPlus {
	return pg.n
}

func (pg *paillierGroup) FromUint(input *num.Uint) (Unit, error) {
	u, err := pg.UZMod.FromUint(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroup) FromNatCT(input *numct.Nat) (Unit, error) {
	u, err := pg.UZMod.FromNatCT(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroup) One() Unit {
	u := pg.UZMod.One()
	u.(*unit).g = pg
	return u
}

func (pg *paillierGroup) Random(prng io.Reader) (Unit, error) {
	u, err := pg.UZMod.Random(prng)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroup) FromBytes(input []byte) (Unit, error) {
	u, err := pg.UZMod.FromBytes(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroup) FromCardinal(input cardinal.Cardinal) (Unit, error) {
	u, err := pg.UZMod.FromCardinal(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroup) FromUint64(value uint64) (Unit, error) {
	u, err := pg.UZMod.FromUint64(value)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroup) EmbedRSA(rsaUnit Unit) (Unit, error) {
	if rsaUnit == nil {
		return nil, errs.NewValue("rsaUnit must not be nil")
	}
	if rsaUnit.Modulus().Value().Equal(pg.N().Value()) == ct.False {
		return nil, errs.NewValue("rsaUnit must be in the RSA group with modulus equal to the Paillier modulus")
	}
	v, err := num.NewUintGivenModulus(rsaUnit.Value(), pg.ModulusCT())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit from rsaUnit")
	}
	return &unit{v: v.Value(), g: pg}, nil
}

func (pg *paillierGroup) LiftToNthResidues(rsaUnit Unit) (Unit, error) {
	if rsaUnit == nil {
		return nil, errs.NewValue("rsaUnit must not be nil")
	}
	if rsaUnit.Modulus().Value().Equal(pg.Modulus().Value()) == ct.False {
		return nil, errs.NewValue("rsaUnit must be in the RSA group with modulus equal to the Paillier modulus")
	}
	lifted, err := pg.FromNatCT(rsaUnit.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to lift rsaUnit to Paillier group")
	}
	return lifted.Exp(pg.n.Nat()), nil
}

func (pg *paillierGroup) Phi(x *numct.Int) (Unit, error) {
	var shiftedPlaintext numct.Nat
	pg.N().ModulusCT().ModInt(&shiftedPlaintext, x)
	var out numct.Nat
	pg.ModulusCT().ModMul(&out, &shiftedPlaintext, pg.N().Value())
	out.Increment()
	return &unit{v: &out, g: pg}, nil
}

func (pg *paillierGroup) Hash(data []byte) (Unit, error) {
	return nil, nil
}

type paillierGroupKnownOrder struct {
	UZMod[*modular.OddPrimeSquareFactors]

	n *num.NatPlus
}

func (pg *paillierGroupKnownOrder) N() *num.NatPlus {
	return pg.n
}

func (pg *paillierGroupKnownOrder) EmbedRSA(rsaUnit Unit) (Unit, error) {
	if rsaUnit == nil {
		return nil, errs.NewValue("rsaUnit must not be nil")
	}
	if rsaUnit.Modulus().Value().Equal(pg.N().Value()) == ct.False {
		return nil, errs.NewValue("rsaUnit must be in the RSA group with modulus equal to the Paillier modulus")
	}
	v, err := num.NewUintGivenModulus(rsaUnit.Value(), pg.ModulusCT())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit from rsaUnit")
	}
	return &unit{v: v.Value(), g: pg}, nil
}

func (pg *paillierGroupKnownOrder) LiftToNthResidues(rsaUnit Unit) (Unit, error) {
	if rsaUnit == nil {
		return nil, errs.NewValue("rsaUnit must not be nil")
	}
	if rsaUnit.Modulus().Value().Equal(pg.Modulus().Value()) == ct.False {
		return nil, errs.NewValue("rsaUnit must be in the RSA group with modulus equal to the Paillier modulus")
	}
	lifted, err := pg.FromNatCT(rsaUnit.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to lift rsaUnit to Paillier group")
	}
	var v numct.Nat
	pg.arith.ExpToN(&v, lifted.Value())
	return &unit{v: &v, g: pg}, nil
}

func (pg *paillierGroupKnownOrder) Arithmetic() *modular.OddPrimeSquareFactors {
	return pg.arith
}

func (pg *paillierGroupKnownOrder) FromUint(input *num.Uint) (Unit, error) {
	u, err := pg.UZMod.FromUint(input)
	if err != nil {
		return nil, err
	}
	// Fix the group pointer to point to the wrapper
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroupKnownOrder) FromNatCT(input *numct.Nat) (Unit, error) {
	u, err := pg.UZMod.FromNatCT(input)
	if err != nil {
		return nil, err
	}
	// Fix the group pointer to point to the wrapper
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroupKnownOrder) One() Unit {
	u := pg.UZMod.One()
	u.(*unit).g = pg
	return u
}

func (pg *paillierGroupKnownOrder) Random(prng io.Reader) (Unit, error) {
	u, err := pg.UZMod.Random(prng)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroupKnownOrder) FromBytes(input []byte) (Unit, error) {
	u, err := pg.UZMod.FromBytes(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroupKnownOrder) FromCardinal(input cardinal.Cardinal) (Unit, error) {
	u, err := pg.UZMod.FromCardinal(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroupKnownOrder) FromUint64(value uint64) (Unit, error) {
	u, err := pg.UZMod.FromUint64(value)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroupKnownOrder) ForgetOrder() PaillierGroup {
	arith, ok := modular.NewSimple(pg.ModulusCT())
	if ok == ct.False {
		panic(errs.NewFailed("failed to create SimpleModulus"))
	}

	return &paillierGroup{
		UZMod: UZMod[*modular.SimpleModulus]{
			zMod:  pg.zMod,
			arith: arith,
		},
		n: pg.n,
	}
}

func (pg *paillierGroupKnownOrder) Phi(x *numct.Int) (Unit, error) {
	var shiftedPlaintext numct.Nat
	pg.N().ModulusCT().ModInt(&shiftedPlaintext, x)
	var out numct.Nat
	pg.ModulusCT().ModMul(&out, &shiftedPlaintext, pg.N().Value())
	out.Increment()
	return &unit{v: &out, g: pg}, nil
}

func (pg *paillierGroupKnownOrder) Hash(data []byte) (Unit, error) {
	return nil, nil
}
