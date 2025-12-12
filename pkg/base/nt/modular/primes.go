package modular

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/crt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// NewOddPrimeFactors constructs an OddPrimeFactors modular arithmetic
// instance from the given odd prime factors p and q.
// Returns ct.False if the inputs are invalid (not odd primes or equal).
func NewOddPrimeFactors(p, q *numct.Nat) (*OddPrimeFactors, ct.Bool) {
	allOk := p.Equal(q).Not() & p.IsProbablyPrime() & q.IsProbablyPrime() & p.IsOdd() & q.IsOdd()

	params, ok := crt.PrecomputePairExtended(p, q)
	allOk &= ok

	// Compute m = p * q for the modulus
	var mNat numct.Nat
	mNat.Mul(p, q)
	m, ok := numct.NewModulus(&mNat)
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
	phi, ok := numct.NewModulus(&phiNat)
	allOk &= ok

	return &OddPrimeFactors{
		Params: params,
		N:      m,
		PhiP:   phiP,
		PhiQ:   phiQ,
		Phi:    phi,
	}, allOk
}

// OddPrimeFactors implements modular arithmetic modulo n = p * q,
// where p and q are distinct odd primes.
type OddPrimeFactors struct {
	Params *crt.ParamsExtended // CRT parameters for p and q
	N      *numct.Modulus      // n = p * q
	PhiP   *numct.Modulus      // φ(p) = p - 1
	PhiQ   *numct.Modulus      // φ(q) = q - 1
	Phi    *numct.Modulus      // φ(n) = (p - 1)*(q - 1)
}

// Modulus returns the modulus n = p * q.
func (m *OddPrimeFactors) Modulus() *numct.Modulus {
	return m.N
}

// MultiplicativeOrder returns the multiplicative order φ(n) = (p-1)*(q-1).
func (m *OddPrimeFactors) MultiplicativeOrder() algebra.Cardinal {
	return cardinal.NewFromNumeric(m.Phi)
}

// ModMul computes out = (a * b) mod n.
func (m *OddPrimeFactors) ModMul(out, a, b *numct.Nat) {
	var ap, aq, bp, bq numct.Nat
	var mp, mq numct.Nat

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		m.Params.P.Mod(&ap, a)
		m.Params.P.Mod(&bp, b)
		m.Params.P.ModMul(&mp, &ap, &bp)
	}()
	go func() {
		defer wg.Done()
		m.Params.Q.Mod(&aq, a)
		m.Params.Q.Mod(&bq, b)
		m.Params.Q.ModMul(&mq, &aq, &bq)
	}()
	wg.Wait()

	out.Set(m.Params.Recombine(&mp, &mq))
}

// ModExp computes out = (base ^ exp) mod n.
func (m *OddPrimeFactors) ModExp(out, base, exp *numct.Nat) {
	var ep, eq, mp, mq numct.Nat
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		m.PhiP.Mod(&ep, exp)
		// Use reduced exponent when base is coprime (Fermat applies),
		// full exponent otherwise.
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

	out.Set(m.Params.Recombine(&mp, &mq))
}

// ModExpI computes out = (base ^ exp) mod n, where exp is a signed integer.
func (m *OddPrimeFactors) ModExpI(out, base *numct.Nat, exp *numct.Int) {
	var out2 numct.Nat
	m.ModExp(out, base, exp.Absed())
	m.ModInv(&out2, out)
	out.CondAssign(exp.IsNegative(), &out2)
}

// ModDiv computes out = (a / b) mod n.
func (m *OddPrimeFactors) ModDiv(out, a, b *numct.Nat) ct.Bool {
	return m.N.ModDiv(out, a, b)
}

// MultiBaseExp computes out[i] = (bases[i] ^ exp) mod n for all i.
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

// ModInv computes out = (a^{-1}) mod n.
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
	out.Set(m.Params.Recombine(&ip, &iq))
	return ok
}

// Lift constructs an OddPrimeSquareFactors modular arithmetic instance
// by lifting the modulus n = p * q to n^2 = p^2 * q^2.
// Returns ct.False if the lift operation fails.
func (m *OddPrimeFactors) Lift() (*OddPrimeSquareFactors, ct.Bool) {
	// TODO: optimize
	out, ok := NewOddPrimeSquareFactors(
		m.Params.PNat,
		m.Params.QNat,
	)
	return out, ok
}
