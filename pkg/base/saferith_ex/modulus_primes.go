package saferith_ex

import (
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"

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
	mBn, err := boring.NewBigNum().SetBytes(m.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	mMontCtx, err := boring.NewBigNumMontCtx(mBn, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNumMont context")
	}
	m1Bn, err := boring.NewBigNum().SetBytes(m1.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	m1MontCtx, err := boring.NewBigNumMontCtx(m1Bn, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNumMont context")
	}
	phiM1Bn, err := boring.NewBigNum().SetBytes(phiM1.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	m2Bn, err := boring.NewBigNum().SetBytes(m2.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	m2MontCtx, err := boring.NewBigNumMontCtx(m2Bn, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNumMont context")
	}
	phiM2Bn, err := boring.NewBigNum().SetBytes(phiM2.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	m1InvM2Bn, err := boring.NewBigNum().SetBytes(m1InvM2.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

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

func (p *primesModulus) Exp(base, exponent *saferith.Nat) (*saferith.Nat, error) {
	bnCtx := boring.NewBigNumCtx()
	baseBn, err := boring.NewBigNum().SetBytes(base.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	exponentBn, err := boring.NewBigNum().SetBytes(exponent.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	baseModM1, err := boring.NewBigNum().Mod(baseBn, p.m1, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	baseModM2, err := boring.NewBigNum().Mod(baseBn, p.m2, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	eModPhiM1, err := boring.NewBigNum().Mod(exponentBn, p.phiM1, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	eModPhiM2, err := boring.NewBigNum().Mod(exponentBn, p.phiM2, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	r1, err := boring.NewBigNum().Exp(baseModM1, eModPhiM1, p.m1, p.m1MontCtx, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	r2, err := boring.NewBigNum().Exp(baseModM2, eModPhiM2, p.m2, p.m2MontCtx, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	t1, err := boring.NewBigNum().ModSub(r2, r1, p.m2)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	t2, err := boring.NewBigNum().ModMul(t1, p.m1InvM2, p.m2, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	t3, err := boring.NewBigNum().ModMul(t2, p.m1, p.m, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	r, err := boring.NewBigNum().ModAdd(t3, r1, p.m)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	rBytes, err := r.Bytes()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	return new(saferith.Nat).SetBytes(rBytes), nil
}

func (p *primesModulus) MultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) ([]*saferith.Nat, error) {
	bnCtx := boring.NewBigNumCtx()
	exponentBn, err := boring.NewBigNum().SetBytes(exponent.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	eModPhiM1, err := boring.NewBigNum().Mod(exponentBn, p.phiM1, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	eModPhiM2, err := boring.NewBigNum().Mod(exponentBn, p.phiM2, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	basesModM1 := make([]*boring.BigNum, len(bases))
	basesModM2 := make([]*boring.BigNum, len(bases))
	for i, base := range bases {
		baseBn, err := boring.NewBigNum().SetBytes(base.Bytes())
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		basesModM1[i], err = boring.NewBigNum().Mod(baseBn, p.m1, bnCtx)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		basesModM2[i], err = boring.NewBigNum().Mod(baseBn, p.m2, bnCtx)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
	}

	var eg errgroup.Group
	r1 := make([]*boring.BigNum, len(bases))
	r2 := make([]*boring.BigNum, len(bases))
	r1Job := func(i int) error {
		var err error
		localBnCtx := boring.NewBigNumCtx()
		r1[i], err = boring.NewBigNum().Exp(basesModM1[i], eModPhiM1, p.m1, p.m1MontCtx, localBnCtx)
		return err //nolint:wrapcheck // deliberate forward
	}
	r2Job := func(i int) error {
		var err error
		localBnCtx := boring.NewBigNumCtx()
		r2[i], err = boring.NewBigNum().Exp(basesModM2[i], eModPhiM2, p.m2, p.m2MontCtx, localBnCtx)
		return err //nolint:wrapcheck // deliberate forward
	}

	for i := 0; i < len(bases); i++ {
		eg.Go(func() error { err := r1Job(i); return err })
		eg.Go(func() error { err := r2Job(i); return err })
	}
	err = eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	results := make([]*saferith.Nat, len(bases))
	for i := 0; i < len(bases); i++ {
		t1, err := boring.NewBigNum().ModSub(r2[i], r1[i], p.m2)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		t2, err := boring.NewBigNum().ModMul(t1, p.m1InvM2, p.m2, bnCtx)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		t3, err := boring.NewBigNum().ModMul(t2, p.m1, p.m, bnCtx)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		r, err := boring.NewBigNum().ModAdd(t3, r1[i], p.m)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		rBytes, err := r.Bytes()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		results[i] = new(saferith.Nat).SetBytes(rBytes)
	}

	return results, nil
}

func (p *primesModulus) MultiExponentExp(base *saferith.Nat, exponents []*saferith.Nat) ([]*saferith.Nat, error) {
	bnCtx := boring.NewBigNumCtx()
	baseBn, err := boring.NewBigNum().SetBytes(base.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	exponentBn := make([]*boring.BigNum, len(exponents))
	for i, e := range exponents {
		exponentBn[i], err = boring.NewBigNum().SetBytes(e.Bytes())
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
	}

	baseModM1, err := boring.NewBigNum().Mod(baseBn, p.m1, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	baseModM2, err := boring.NewBigNum().Mod(baseBn, p.m2, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	eModPhiM1 := make([]*boring.BigNum, len(exponentBn))
	eModPhiM2 := make([]*boring.BigNum, len(exponentBn))
	for i, e := range exponentBn {
		eModPhiM1[i], err = boring.NewBigNum().Mod(e, p.phiM1, bnCtx)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		eModPhiM2[i], err = boring.NewBigNum().Mod(e, p.phiM2, bnCtx)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
	}

	var eg errgroup.Group
	r1 := make([]*boring.BigNum, len(exponents))
	r2 := make([]*boring.BigNum, len(exponents))
	r1Job := func(i int) error {
		var err error
		localBnCtx := boring.NewBigNumCtx()
		r1[i], err = boring.NewBigNum().Exp(baseModM1, eModPhiM1[i], p.m1, p.m1MontCtx, localBnCtx)
		return err //nolint:wrapcheck // deliberate forward
	}
	r2Job := func(i int) error {
		var err error
		localBnCtx := boring.NewBigNumCtx()
		r2[i], err = boring.NewBigNum().Exp(baseModM2, eModPhiM2[i], p.m2, p.m2MontCtx, localBnCtx)
		return err //nolint:wrapcheck // deliberate forward
	}

	for i := 0; i < len(exponents); i++ {
		eg.Go(func() error { err := r1Job(i); return err })
		eg.Go(func() error { err := r2Job(i); return err })
	}
	err = eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	results := make([]*saferith.Nat, len(exponents))
	for i := 0; i < len(exponents); i++ {
		t1, err := boring.NewBigNum().ModSub(r2[i], r1[i], p.m2)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		t2, err := boring.NewBigNum().ModMul(t1, p.m1InvM2, p.m2, bnCtx)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		t3, err := boring.NewBigNum().ModMul(t2, p.m1, p.m, bnCtx)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		r, err := boring.NewBigNum().ModAdd(t3, r1[i], p.m)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		rBytes, err := r.Bytes()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}

		results[i] = new(saferith.Nat).SetBytes(rBytes)
	}

	return results, nil
}
