package saferith_ex

import (
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex/internal/boring"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

type primesModulus struct {
	mNat *saferith.Modulus

	m        *boring.BigNum
	mMontCtx *boring.BigNumMontCtx

	m1        *boring.BigNum
	m1MontCtx *boring.BigNumMontCtx
	phiM1     *boring.BigNum

	m2        *boring.BigNum
	m2MontCtx *boring.BigNumMontCtx
	phiM2     *boring.BigNum

	m1InvM2 *boring.BigNum
}

// NewTwoPrimePowersModulus creates modulus of the form: p^s * q^t
func NewTwoPrimePowersModulus(p *saferith.Nat, s uint, q *saferith.Nat, t uint) (Modulus, error) {
	if p == nil || s < 1 || !p.Big().ProbablyPrime(8) {
		return nil, errs.NewValidation("invalid p^s")
	}
	if q == nil || t < 1 || !q.Big().ProbablyPrime(8) {
		return nil, errs.NewValidation("invalid q^t")
	}

	m := new(saferith.Nat).Mul(p, q, -1)
	pMinusOne := utils.DecrementNat(p)
	m1 := p
	phiM1 := pMinusOne
	for i := uint(1); i < s; i++ {
		m = new(saferith.Nat).Mul(m, p, -1)
		m1 = new(saferith.Nat).Mul(m1, p, -1)
		phiM1 = new(saferith.Nat).Mul(phiM1, p, -1)
	}

	qMinusOne := utils.DecrementNat(q)
	m2 := q
	phiM2 := qMinusOne
	for i := uint(1); i < t; i++ {
		m = new(saferith.Nat).Mul(m, q, -1)
		m2 = new(saferith.Nat).Mul(m2, q, -1)
		phiM2 = new(saferith.Nat).Mul(phiM2, q, -1)
	}

	if bigger, _, _ := m1.Cmp(m2); bigger == 1 {
		m2, m1 = m1, m2
		phiM2, phiM1 = phiM1, phiM2
	}

	m1InvM2 := new(saferith.Nat).ModInverse(m1, saferith.ModulusFromNat(m2))
	bnCtx := boring.NewBigNumCtx()
	mBn := boring.NewBigNum().SetBytes(m.Bytes())
	mMontCtx := boring.NewBigNumMontCtx(mBn, bnCtx)
	m1Bn := boring.NewBigNum().SetBytes(m1.Bytes())
	m1MontCtx := boring.NewBigNumMontCtx(m1Bn, bnCtx)
	phiM1Bn := boring.NewBigNum().SetBytes(phiM1.Bytes())
	m2Bn := boring.NewBigNum().SetBytes(m2.Bytes())
	m2MontCtx := boring.NewBigNumMontCtx(m2Bn, bnCtx)
	phiM2Bn := boring.NewBigNum().SetBytes(phiM2.Bytes())
	m1InvM2Bn := boring.NewBigNum().SetBytes(m1InvM2.Bytes())

	return &primesModulus{
		mNat:      saferith.ModulusFromNat(m),
		m:         mBn,
		mMontCtx:  mMontCtx,
		m1:        m1Bn,
		m1MontCtx: m1MontCtx,
		phiM1:     phiM1Bn,
		m2:        m2Bn,
		m2MontCtx: m2MontCtx,
		phiM2:     phiM2Bn,
		m1InvM2:   m1InvM2Bn,
	}, nil
}

func (p *primesModulus) Modulus() *saferith.Modulus {
	return p.mNat
}

func (p *primesModulus) Nat() *saferith.Nat {
	return p.mNat.Nat()
}

func (p *primesModulus) Exp(base, exponent *saferith.Nat) *saferith.Nat {
	bnCtx := boring.NewBigNumCtx()
	baseBn := boring.NewBigNum().SetBytes(base.Bytes())
	exponentBn := boring.NewBigNum().SetBytes(exponent.Bytes())

	baseModM1 := boring.NewBigNum().Mod(baseBn, p.m1, bnCtx)
	baseModM2 := boring.NewBigNum().Mod(baseBn, p.m2, bnCtx)
	eModPhiM1 := boring.NewBigNum().Mod(exponentBn, p.phiM1, bnCtx)
	eModPhiM2 := boring.NewBigNum().Mod(exponentBn, p.phiM2, bnCtx)
	r1 := boring.NewBigNum().Exp(baseModM1, eModPhiM1, p.m1, p.m1MontCtx, bnCtx)
	r2 := boring.NewBigNum().Exp(baseModM2, eModPhiM2, p.m2, p.m2MontCtx, bnCtx)
	t1 := boring.NewBigNum().ModSub(r2, r1, p.m2)
	t2 := boring.NewBigNum().ModMul(t1, p.m1InvM2, p.m2, bnCtx)
	t3 := boring.NewBigNum().ModMul(t2, p.m1, p.m, bnCtx)
	r := boring.NewBigNum().ModAdd(t3, r1, p.m)

	return new(saferith.Nat).SetBytes(r.Bytes())
}

func (p *primesModulus) MultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) []*saferith.Nat {
	bnCtx := boring.NewBigNumCtx()
	exponentBn := boring.NewBigNum().SetBytes(exponent.Bytes())
	eModPhiM1 := boring.NewBigNum().Mod(exponentBn, p.phiM1, bnCtx)
	eModPhiM2 := boring.NewBigNum().Mod(exponentBn, p.phiM2, bnCtx)

	basesModM1 := make([]*boring.BigNum, len(bases))
	basesModM2 := make([]*boring.BigNum, len(bases))
	for i, base := range bases {
		baseBn := boring.NewBigNum().SetBytes(base.Bytes())
		basesModM1[i] = boring.NewBigNum().Mod(baseBn, p.m1, bnCtx)
		basesModM2[i] = boring.NewBigNum().Mod(baseBn, p.m2, bnCtx)
	}

	var wg sync.WaitGroup
	r1 := make([]*boring.BigNum, len(bases))
	r2 := make([]*boring.BigNum, len(bases))
	r1Job := func(i int) {
		localBnCtx := boring.NewBigNumCtx()
		r1[i] = boring.NewBigNum().Exp(basesModM1[i], eModPhiM1, p.m1, p.m1MontCtx, localBnCtx)
		wg.Done()
	}
	r2Job := func(i int) {
		localBnCtx := boring.NewBigNumCtx()
		r2[i] = boring.NewBigNum().Exp(basesModM2[i], eModPhiM2, p.m2, p.m2MontCtx, localBnCtx)
		wg.Done()
	}

	wg.Add(len(bases) + len(bases))
	for i := 0; i < len(bases); i++ {
		go r1Job(i)
		go r2Job(i)
	}
	wg.Wait()

	results := make([]*saferith.Nat, len(bases))
	for i := 0; i < len(bases); i++ {
		t1 := boring.NewBigNum().ModSub(r2[i], r1[i], p.m2)
		t2 := boring.NewBigNum().ModMul(t1, p.m1InvM2, p.m2, bnCtx)
		t3 := boring.NewBigNum().ModMul(t2, p.m1, p.m, bnCtx)
		r := boring.NewBigNum().ModAdd(t3, r1[i], p.m)
		results[i] = new(saferith.Nat).SetBytes(r.Bytes())
	}

	return results
}

func (p *primesModulus) MultiExponentExp(base *saferith.Nat, exponents []*saferith.Nat) []*saferith.Nat {
	bnCtx := boring.NewBigNumCtx()
	baseBn := boring.NewBigNum().SetBytes(base.Bytes())

	exponentBn := make([]*boring.BigNum, len(exponents))
	for i, e := range exponents {
		exponentBn[i] = boring.NewBigNum().SetBytes(e.Bytes())
	}

	baseModM1 := boring.NewBigNum().Mod(baseBn, p.m1, bnCtx)
	baseModM2 := boring.NewBigNum().Mod(baseBn, p.m2, bnCtx)
	eModPhiM1 := make([]*boring.BigNum, len(exponentBn))
	eModPhiM2 := make([]*boring.BigNum, len(exponentBn))
	for i, e := range exponentBn {
		eModPhiM1[i] = boring.NewBigNum().Mod(e, p.phiM1, bnCtx)
		eModPhiM2[i] = boring.NewBigNum().Mod(e, p.phiM2, bnCtx)
	}

	var wg sync.WaitGroup
	r1 := make([]*boring.BigNum, len(exponents))
	r2 := make([]*boring.BigNum, len(exponents))
	r1Job := func(i int) {
		localBnCtx := boring.NewBigNumCtx()
		r1[i] = boring.NewBigNum().Exp(baseModM1, eModPhiM1[i], p.m1, p.m1MontCtx, localBnCtx)
		wg.Done()
	}
	r2Job := func(i int) {
		localBnCtx := boring.NewBigNumCtx()
		r2[i] = boring.NewBigNum().Exp(baseModM2, eModPhiM2[i], p.m2, p.m2MontCtx, localBnCtx)
		wg.Done()
	}

	wg.Add(len(exponents) + len(exponents))
	for i := 0; i < len(exponents); i++ {
		go r1Job(i)
		go r2Job(i)
	}
	wg.Wait()

	results := make([]*saferith.Nat, len(exponents))
	for i := 0; i < len(exponents); i++ {
		t1 := boring.NewBigNum().ModSub(r2[i], r1[i], p.m2)
		t2 := boring.NewBigNum().ModMul(t1, p.m1InvM2, p.m2, bnCtx)
		t3 := boring.NewBigNum().ModMul(t2, p.m1, p.m, bnCtx)
		r := boring.NewBigNum().ModAdd(t3, r1[i], p.m)
		results[i] = new(saferith.Nat).SetBytes(r.Bytes())
	}

	return results
}
