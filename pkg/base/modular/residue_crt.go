package modular

import (
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	saferithUtils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
)

var (
	_ CrtResidueParams = (*crtResidueParams)(nil)
)

type CrtResidueParams interface {
	ResidueParams

	GetM1() ResidueParams
	GetM2() ResidueParams
	GetPhiM1() *saferith.Modulus
	GetPhiM2() *saferith.Modulus
	GetM1InvM2() *saferith.Nat
}

type crtResidueParams struct {
	m *saferith.Modulus

	m1      ResidueParams
	m2      ResidueParams
	phiM1   *saferith.Modulus
	phiM2   *saferith.Modulus
	m1InvM2 *saferith.Nat
}

func NewCrtResidueParams(p *saferith.Nat, pn uint, q *saferith.Nat, qn uint) (CrtResidueParams, error) {
	if pn < 1 || qn < 1 {
		return nil, errs.NewArgument("prime powers cannot be zero")
	}
	if !p.Big().ProbablyPrime(16) || !q.Big().ProbablyPrime(16) {
		return nil, errs.NewArgument("p & q must be primes")
	}

	m := new(saferith.Nat).Mul(p, q, -1)
	pMinusOne := saferithUtils.NatDec(p)
	m1 := p
	phiM1 := pMinusOne
	for i := uint(1); i < pn; i++ {
		m = new(saferith.Nat).Mul(m, p, -1)
		m1 = new(saferith.Nat).Mul(m1, p, -1)
		phiM1 = new(saferith.Nat).Mul(phiM1, p, -1)
	}

	qMinusOne := saferithUtils.NatDec(q)
	m2 := q
	phiM2 := qMinusOne
	for i := uint(1); i < qn; i++ {
		m = new(saferith.Nat).Mul(m, q, -1)
		m2 = new(saferith.Nat).Mul(m2, q, -1)
		phiM2 = new(saferith.Nat).Mul(phiM2, q, -1)
	}

	if saferithUtils.NatIsLess(m2, m1) {
		m2, m1 = m1, m2
		phiM2, phiM1 = phiM1, phiM2
	}

	m1ResidueParams, err := NewOddResidueParams(m1)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create m1 residue params")
	}

	m2ResidueParams, err := NewOddResidueParams(m2)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create m2 residue params")
	}

	m1InvM2 := new(saferith.Nat).ModInverse(m1, m2ResidueParams.GetModulus())

	residueParams := &crtResidueParams{
		m:       saferith.ModulusFromNat(m),
		m1:      m1ResidueParams,
		m2:      m2ResidueParams,
		phiM1:   saferith.ModulusFromNat(phiM1),
		phiM2:   saferith.ModulusFromNat(phiM2),
		m1InvM2: m1InvM2,
	}

	return residueParams, nil
}

func (p *crtResidueParams) ModExp(base, exponent *saferith.Nat) (*saferith.Nat, error) {
	eModPhiM1 := new(saferith.Nat).Mod(exponent, p.phiM1)
	eModPhiM2 := new(saferith.Nat).Mod(exponent, p.phiM2)

	r1, err := p.m1.ModExp(base, eModPhiM1)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute m1 exponent")
	}
	r2, err := p.m2.ModExp(base, eModPhiM2)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute m2 exponent")
	}

	t1 := new(saferith.Nat).ModSub(r2, r1, p.m2.GetModulus())
	t2 := new(saferith.Nat).ModMul(t1, p.m1InvM2, p.m2.GetModulus())
	t3 := new(saferith.Nat).ModMul(t2, p.m1.GetModulus().Nat(), p.m)
	result := new(saferith.Nat).ModAdd(t3, r1, p.m)

	return result, nil
}

func (p *crtResidueParams) ModMultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) ([]*saferith.Nat, error) {
	eModPhiM1 := new(saferith.Nat).Mod(exponent, p.phiM1)
	eModPhiM2 := new(saferith.Nat).Mod(exponent, p.phiM2)

	var r1s, r2s []*saferith.Nat
	var errGroup errgroup.Group
	errGroup.Go(func() error {
		var err error
		r1s, err = p.m1.ModMultiBaseExp(bases, eModPhiM1)
		return err //nolint:wrapcheck // checked on errGroup.Wait
	})
	errGroup.Go(func() error {
		var err error
		r2s, err = p.m2.ModMultiBaseExp(bases, eModPhiM2)
		return err //nolint:wrapcheck // checked on errGroup.Wait
	})
	err := errGroup.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exponent")
	}

	results := make([]*saferith.Nat, len(bases))
	for i := range results {
		t1 := new(saferith.Nat).ModSub(r2s[i], r1s[i], p.m2.GetModulus())
		t2 := new(saferith.Nat).ModMul(t1, p.m1InvM2, p.m2.GetModulus())
		t3 := new(saferith.Nat).ModMul(t2, p.m1.GetModulus().Nat(), p.m)
		results[i] = new(saferith.Nat).ModAdd(t3, r1s[i], p.m)
	}

	return results, nil
}

func (p *crtResidueParams) GetModulus() *saferith.Modulus {
	return p.m
}

func (p *crtResidueParams) GetM1() ResidueParams {
	return p.m1
}

func (p *crtResidueParams) GetM2() ResidueParams {
	return p.m2
}

func (p *crtResidueParams) GetPhiM1() *saferith.Modulus {
	return p.phiM1
}

func (p *crtResidueParams) GetPhiM2() *saferith.Modulus {
	return p.phiM2
}

func (p *crtResidueParams) GetM1InvM2() *saferith.Nat {
	return p.m1InvM2
}
