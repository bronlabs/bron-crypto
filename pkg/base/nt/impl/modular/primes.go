package modular

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl/crt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
)

func NewOddPrimeFactors[MM internal.ModulusMutablePtr[N, MMT], MF internal.ModulusMutablePtr[N, MFT], N internal.NatMutablePtr[N, NT], MMT, MFT, NT any](
	p, q N,
) (*OddPrimeFactors[MM, MF, N, MMT, MFT, NT], ct.Bool) {
	allOk := p.Equal(q).Not() & p.IsProbablyPrime() & q.IsProbablyPrime() & p.IsOdd() & q.IsOdd()

	var pModulusT MFT
	ok := MF(&pModulusT).SetNat(p)
	allOk &= ok

	params, ok := crt.PrecomputePairExtended(MF(&pModulusT), q)
	allOk &= ok

	// Compute m = p * q for the modulus
	var mNatT NT
	N(&mNatT).Mul(p, q)
	var mModulusT MMT
	ok = MM(&mModulusT).SetNat(N(&mNatT))
	allOk &= ok

	// Compute phi(p) = p-1 and phi(q) = q-1
	var phiPNatT, phiQNatT NT
	N(&phiPNatT).Set(p)
	N(&phiPNatT).Decrement()
	N(&phiQNatT).Set(q)
	N(&phiQNatT).Decrement()

	return &OddPrimeFactors[MM, MF, N, MMT, MFT, NT]{
		params:  params,
		modulus: mModulusT,
		phiP:    phiPNatT,
		phiQ:    phiQNatT,
	}, allOk
}

type OddPrimeFactors[MM internal.ModulusMutablePtr[N, MMT], MF internal.ModulusMutablePtr[N, MFT], N internal.NatMutablePtr[N, NT], MMT, MFT, NT any] struct {
	params  *crt.ParamsPairExtended[MF, N, MFT, NT]
	modulus MMT
	phiP    NT // phi(p) = p-1 as Nat
	phiQ    NT // phi(q) = q-1 as Nat
}

func (m *OddPrimeFactors[MM, MF, N, MMT, MFT, NT]) Modulus() MM {
	return MM(&m.modulus)
}

func (m *OddPrimeFactors[MM, MF, N, MMT, MFT, NT]) Exp(out, base, exp N) ct.Bool {
	// Euler-totient theorem: Reduce the exponent modulo φ(p) and φ(q).
	var ep, eq NT
	N(&ep).Mod(exp, N(&m.phiP))
	N(&eq).Mod(exp, N(&m.phiQ))
	N(&ep).CondAssign(base.Coprime(N(&m.params.PNat)), exp, N(&ep))
	N(&eq).CondAssign(base.Coprime(N(&m.params.Q)), exp, N(&eq))

	// Compute base^ep mod p and base^eq mod q in parallel.
	var mp, mq NT
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		MF(&m.params.P).ModExp(N(&mp), base, N(&ep))
	}()
	go func() {
		defer wg.Done()
		MF(&m.params.QModulus).ModExp(N(&mq), base, N(&eq))
	}()
	wg.Wait()

	// CRT recombine into modulo n = p*q.
	res := m.params.Recombine(N(&mp), N(&mq))
	*out = *res
	return ct.True
}

func NewOddPrimeFactorsMulti[MM internal.ModulusMutablePtr[N, MMT], MF internal.ModulusMutablePtr[N, MFT], N internal.NatMutablePtr[N, NT], MFT, MMT, NT any](
	ps ...N,
) (*OddPrimeFactorsMulti[MM, MF, N, MMT, MFT, NT], ct.Bool) {
	k := len(ps)
	params, allOk := crt.Precompute[MM, MF](ps...)

	phis := make([]N, k)

	for i := range k {
		// must be odd prime
		// allOk &= ps[i].IsProbablyPrime() & ps[i].IsOdd()
		allOk &= ps[i].IsOdd()

		// compute phi(p_i) = p_i - 1
		var phi NT
		N(&phi).Set(ps[i])
		N(&phi).Decrement()
		phis[i] = N(&phi).Clone()

		for j := i + 1; j < k; j++ {
			allOk &= ps[i].Coprime(ps[j])
			// allOk &= ps[j].Equal(ps[i]).Not()
		}
	}

	return &OddPrimeFactorsMulti[MM, MF, N, MMT, MFT, NT]{
		params:  params,
		modulus: params.Modulus,
		phis:    phis,
	}, allOk
}

type OddPrimeFactorsMulti[MM internal.ModulusMutablePtr[N, MMT], MF internal.ModulusMutablePtr[N, MFT], N internal.NatMutablePtr[N, NT], MMT, MFT, NT any] struct {
	params  *crt.Params[MM, MF, N, MMT, MFT, NT]
	modulus MM
	phis    []N
}

func (m *OddPrimeFactorsMulti[MM, MF, N, MMT, MFT, NT]) Modulus() MM {
	return m.modulus
}

func (m *OddPrimeFactorsMulti[MM, MF, N, MMT, MFT, NT]) Exp(out, base, exp N) ct.Bool {
	eps := make([]NT, m.params.NumFactors)
	for i := range m.params.NumFactors {
		N(&eps[i]).Mod(exp, m.phis[i])
		N(&eps[i]).CondAssign(base.Coprime(m.params.Factors[i].Nat()), exp, N(&eps[i]))
	}
	mpsT := make([]NT, m.params.NumFactors)
	mps := make([]N, m.params.NumFactors)
	var wg sync.WaitGroup
	wg.Add(m.params.NumFactors)
	for i := range m.params.NumFactors {
		go func(i int) {
			defer wg.Done()
			m.params.Factors[i].ModExp(N(&mpsT[i]), base, &eps[i])
			mps[i] = N(&mpsT[i])
		}(i)
	}
	wg.Wait()
	res, ok := m.params.Recombine(mps)
	*out = *res
	return ok
}
