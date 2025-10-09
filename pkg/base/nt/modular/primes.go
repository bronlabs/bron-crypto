package modular

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/crt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func NewOddPrimeFactors(p, q *numct.Nat) (*OddPrimeFactors, ct.Bool) {
	allOk := p.Equal(q).Not() & p.IsProbablyPrime() & q.IsProbablyPrime() & p.IsOdd() & q.IsOdd()

	params, ok := crt.PrecomputePairExtended[*numct.ModulusOddPrime](p, q)
	allOk &= ok

	// Compute m = p * q for the modulus
	var mNat numct.Nat
	mNat.Mul(p, q)
	m, ok := numct.NewModulusOdd(&mNat)
	allOk &= ok

	// Compute phi(p) = p-1 and phi(q) = q-1
	var phiPnat, phiQnat numct.Nat
	phiPnat.Set(p.Clone())
	phiPnat.Decrement()
	phiQnat.Set(q.Clone())
	phiQnat.Decrement()

	phiP, ok := numct.NewModulus(&phiPnat)
	allOk &= ok
	phiQ, ok := numct.NewModulus(&phiQnat)
	allOk &= ok

	var phiNat numct.Nat
	phiNat.Mul(&phiPnat, &phiQnat)
	phi, ok := numct.NewModulusNonZero(&phiNat)
	allOk &= ok

	return &OddPrimeFactors{
		Params: params,
		N:      m,
		PhiP:   phiP,
		PhiQ:   phiQ,
		Phi:    phi,
	}, allOk
}

type OddPrimeFactors struct {
	Params *crt.ParamsExtended[*numct.ModulusOddPrime]
	N      *numct.ModulusOdd
	PhiP   numct.Modulus
	PhiQ   numct.Modulus
	Phi    numct.Modulus
}

func (m *OddPrimeFactors) Modulus() numct.Modulus {
	return m.N
}

func (m *OddPrimeFactors) ModExp(out, base, exp *numct.Nat) {
	// Compute base^ep mod p and base^eq mod q in parallel.
	var ep, eq, mp, mq numct.Nat
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		m.PhiP.Mod(&ep, exp)
		ep.Select(base.Coprime(m.Params.PNat), exp, &ep)
		(m.Params.P).ModExp(&mp, base, &ep)
	}()
	go func() {
		defer wg.Done()
		m.PhiQ.Mod(&eq, exp)
		eq.Select(base.Coprime(m.Params.QNat), exp, &eq)
		m.Params.Q.ModExp(&mq, base, &eq)
	}()
	wg.Wait()

	// CRT recombine into modulo n = p*q.
	out.Set(m.Params.Recombine(&mp, &mq))
}

func (m *OddPrimeFactors) MultiBaseExp(out []*numct.Nat, bases []*numct.Nat, exp *numct.Nat) {
	if len(out) != len(bases) {
		panic("out and bases must have the same length")
	}
	k := len(bases)

	var ep, eq numct.Nat
	m.PhiP.Mod(&ep, exp)
	m.PhiQ.Mod(&eq, exp)

	var wg sync.WaitGroup
	wg.Add(k)
	for i := range k {
		go func(i int) {
			defer wg.Done()
			bi := bases[i]
			var mp, mq numct.Nat
			var wgInner sync.WaitGroup
			wgInner.Add(2)
			go func() {
				defer wgInner.Done()
				var epi numct.Nat
				epi.Select(bi.Coprime(m.Params.PNat), exp, &ep)
				m.Params.P.ModExp(&mp, bi, &epi)
			}()
			go func() {
				defer wgInner.Done()
				var eqi numct.Nat
				eqi.Select(bi.Coprime(m.Params.QNat), exp, &eq)
				m.Params.Q.ModExp(&mq, bi, &eqi)
			}()
			wgInner.Wait()
			out[i].Set(m.Params.Recombine(&mp, &mq))
		}(i)
	}
	wg.Wait()
}

func (m *OddPrimeFactors) ModInv(out, a *numct.Nat) ct.Bool {
	var ap, aq numct.Nat
	var ip, iq numct.Nat
	var okP, okQ ct.Bool

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		(m.Params.P).Mod(&ap, a)
		okP = (m.Params.P).ModInv(&ip, &ap)
	}()
	go func() {
		defer wg.Done()
		(m.Params.Q).Mod(&aq, a)
		okQ = (m.Params.Q).ModInv(&iq, &aq)
	}()
	wg.Wait()

	ok := okP & okQ
	// CRT recombine inverse residues to get a^{-1} mod n
	out.Set(m.Params.Recombine(&ip, &iq))
	return ok
}

func NewOddPrimeFactorsMulti(ps ...*numct.Nat) (*OddPrimeFactorsMulti, ct.Bool) {
	k := len(ps)
	params, allOk := crt.PrecomputeMulti[*numct.ModulusOddPrime](ps...)

	phis := make([]numct.Modulus, k)
	for i := range k {
		// must be odd prime
		allOk &= ps[i].IsProbablyPrime() & ps[i].IsOdd()

		// compute phi(p_i) = p_i - 1
		phiiNat := ps[i].Clone()
		phiiNat.Decrement()

		for j := i + 1; j < k; j++ {
			// allOk &= ps[i].Coprime(ps[j])
			allOk &= ps[j].Equal(ps[i]).Not()
		}

		phii, ok := numct.NewModulus(phiiNat)
		allOk &= ok
		phis[i] = phii
	}
	return &OddPrimeFactorsMulti{
		params: params,
		phis:   phis,
	}, allOk
}

type OddPrimeFactorsMulti struct {
	params *crt.ParamsMulti[*numct.ModulusOddPrime]
	phis   []numct.Modulus
}

func (m *OddPrimeFactorsMulti) Modulus() numct.Modulus {
	return m.params.Modulus
}

func (m *OddPrimeFactorsMulti) ModExp(out, base, exp *numct.Nat) {
	eps := make([]*numct.Nat, m.params.NumFactors)
	for i := range m.params.NumFactors {
		m.phis[i].Mod(eps[i], exp)
		eps[i].Select(base.Coprime(m.params.Factors[i].Nat()), exp, eps[i])
	}
	mps := make([]*numct.Nat, m.params.NumFactors)
	var wg sync.WaitGroup
	wg.Add(m.params.NumFactors)
	for i := range m.params.NumFactors {
		go func(i int) {
			defer wg.Done()
			m.params.Factors[i].ModExp(mps[i], base, eps[i])
		}(i)
	}
	wg.Wait()
	res, _ := m.params.Recombine(mps...)
	out.Set(res)
}

func (m *OddPrimeFactorsMulti) MultiBaseExp(out []*numct.Nat, bases []*numct.Nat, exp *numct.Nat) {
	if len(out) != len(bases) {
		panic("out and bases must have the same length")
	}
	k := len(bases)
	eps := make([]*numct.Nat, k)
	for i := range k {
		m.phis[i].Mod(eps[i], exp)
	}
	var wg sync.WaitGroup
	wg.Add(k)
	for i := range k {
		go func(i int) {
			defer wg.Done()
			bi := bases[i]
			mps := make([]*numct.Nat, m.params.NumFactors)
			var wgInner sync.WaitGroup
			wgInner.Add(m.params.NumFactors)
			for j := range m.params.NumFactors {
				go func(j int) {
					defer wgInner.Done()
					eps[j].Select(bi.Coprime(m.params.Factors[j].Nat()), exp, eps[j])
					m.params.Factors[j].ModExp(mps[j], bi, eps[j])
				}(j)
			}
			wgInner.Wait()
			res, _ := m.params.Recombine(mps...)
			out[i].Set(res)
		}(i)
	}
	wg.Wait()
}

func (m *OddPrimeFactorsMulti) ModInv(out, a *numct.Nat) ct.Bool {
	mps := make([]*numct.Nat, m.params.NumFactors)
	var wg sync.WaitGroup
	wg.Add(m.params.NumFactors)
	for i := range m.params.NumFactors {
		go func(i int) {
			defer wg.Done()
			m.params.Factors[i].ModInv(mps[i], a)
		}(i)
	}
	wg.Wait()
	res, ok := m.params.Recombine(mps...)
	out.Set(res)
	return ok
}
