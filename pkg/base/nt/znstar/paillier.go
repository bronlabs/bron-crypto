package znstar

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func PaillierGroupsAreEqual[G PaillierGroup](a, b G) bool {
	return a.Order().Equal(b.Order()) && (a.N().Value().Equal(b.N().Value()))&a.ModulusCT().Nat().Equal(b.ModulusCT().Nat()) == ct.True
}

type PaillierGroup interface {
	UnitGroup
	N() *num.NatPlus
	EmbedRSA(Unit) (Unit, error)
	LiftToNthResidues(rsaUnit Unit) (Unit, error)
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
	// Order of (Z/n²Z)* is n·φ(n) = n·(p-1)(q-1)
	pMinus1 := p.Lift().Sub(num.Z().FromUint64(1))
	qMinus1 := q.Lift().Sub(num.Z().FromUint64(1))
	phi := pMinus1.Mul(qMinus1)
	order := cardinal.NewFromBig(n.Lift().Mul(phi).Big())
	return &paillierGroupKnownOrder{
		paillierGroup: paillierGroup{
			UZMod: UZMod[*modular.OddPrimeSquareFactors]{
				zMod:  zMod,
				order: order,
				arith: exp,
			},
			n: n,
		},
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
	return &paillierGroup{
		UZMod: UZMod[*modular.OddPrimeSquareFactors]{
			zMod:  zMod,
			order: cardinal.Unknown(),
		},
		n: n,
	}, nil
}

type paillierGroup struct {
	UZMod[*modular.OddPrimeSquareFactors]
	n *num.NatPlus
}

func (pg *paillierGroup) N() *num.NatPlus {
	return pg.n
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

type paillierGroupKnownOrder struct {
	paillierGroup
}

func (pg *paillierGroupKnownOrder) Arithmetic() *modular.OddPrimeSquareFactors {
	return pg.arith
}

func (pg *paillierGroupKnownOrder) ForgetOrder() PaillierGroup {
	return &paillierGroup{
		UZMod: UZMod[*modular.OddPrimeSquareFactors]{
			zMod:  pg.zMod,
			order: cardinal.Unknown(),
			arith: new(modular.OddPrimeSquareFactors),
		},
		n: pg.n,
	}
}

func (pg *paillierGroupKnownOrder) FromUint(input *num.Uint) (Unit, error) {
	u, err := pg.paillierGroup.FromUint(input)
	if err != nil {
		return nil, err
	}
	// Fix the group pointer to point to the known order wrapper
	u.(*unit).g = pg
	return u, nil
}

func (pg *paillierGroupKnownOrder) EmbedRSA(rsaUnit Unit) (Unit, error) {
	out, err := pg.paillierGroup.EmbedRSA(rsaUnit)
	if err != nil {
		return nil, err
	}
	out.(*unit).g = pg
	return out, nil
}

func (pg *paillierGroupKnownOrder) LiftToNthResidues(rsaUnit Unit) (Unit, error) {
	if rsaUnit == nil {
		return nil, errs.NewValue("rsaUnit must not be nil")
	}
	// if rsaUnit.Modulus().Value().Equal(pg.Modulus().Value()) == ct.False {
	// 	return nil, errs.NewValue("rsaUnit must be in the RSA group with modulus equal to the Paillier modulus")
	// }
	var rn numct.Nat
	pg.arith.ExpToN(&rn, rsaUnit.Value())
	v, err := num.NewUintGivenModulus(&rn, pg.arith.N2)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit from rsaUnit")
	}
	return &unit{v: v.Value(), g: pg}, nil
}
