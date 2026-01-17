package modular

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/crt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// NewOddPrimeSquare constructs an OddPrimeSquare modular arithmetic
// instance from the given odd prime factor p.
// Returns ct.False if the input is invalid (not an odd prime).
func NewOddPrimeSquare(oddPrimeFactor *numct.Nat) (m *OddPrimeSquare, ok ct.Bool) {
	allOk := oddPrimeFactor.IsProbablyPrime() & oddPrimeFactor.IsOdd()

	p, ok := numct.NewModulus(oddPrimeFactor)
	allOk &= ok

	// Compute φ(p) = p - 1
	phiPNat := oddPrimeFactor.Clone()
	phiPNat.Decrement() // φ(p) = p - 1

	// Compute φ(p^2) = p * (p - 1)
	var phiP2Nat numct.Nat
	phiP2Nat.Mul(phiPNat, oddPrimeFactor) // φ(p^2) = p * (p - 1)

	phiP, ok := numct.NewModulus(phiPNat)
	allOk &= ok
	phiP2, ok := numct.NewModulus(&phiP2Nat)
	allOk &= ok

	// Compute p^2
	var p2Nat numct.Nat
	p2Nat.Mul(oddPrimeFactor, oddPrimeFactor) // p^2

	p2, ok := numct.NewModulus(&p2Nat)
	allOk &= ok

	return &OddPrimeSquare{
		Factor:     p,
		Squared:    p2,
		PhiFactor:  phiP,
		PhiSquared: phiP2,
	}, allOk
}

// OddPrimeSquare implements modular arithmetic modulo p^2,
// where p is an odd prime.
type OddPrimeSquare struct {
	Factor     *numct.Modulus // p
	Squared    *numct.Modulus // p^2
	PhiFactor  *numct.Modulus // φ(p) = p - 1
	PhiSquared *numct.Modulus // φ(p^2) = p * (p - 1)
}

// ModExp computes out = (base ^ exp) mod p^2.
func (m *OddPrimeSquare) Modulus() *numct.Modulus {
	return m.Squared
}

// ModExp computes out = (base ^ exp) mod p^2.
func (m *OddPrimeSquare) MultiplicativeOrder() algebra.Cardinal {
	return cardinal.NewFromNumeric(m.PhiSquared)
}

// NewOddPrimeSquareFactors constructs an OddPrimeSquareFactors modular arithmetic
// instance from the given odd prime factors p and q.
// Returns ct.False if the inputs are invalid (not distinct).
func NewOddPrimeSquareFactors(firstPrime, secondPrime *numct.Nat) (m *OddPrimeSquareFactors, ok ct.Bool) {
	allOk := firstPrime.Equal(secondPrime).Not()

	// Clone the inputs to avoid any possibility of mutation
	firstPrimeClone := firstPrime.Clone()
	secondPrimeClone := secondPrime.Clone()

	p, ok := NewOddPrimeSquare(firstPrimeClone)
	allOk &= ok
	q, ok := NewOddPrimeSquare(secondPrimeClone)
	allOk &= ok

	crtModN, ok := crt.NewParamsExtended(p.Factor, q.Factor)
	allOk &= ok

	crtModN2, ok := crt.NewParamsExtended(p.Squared, q.Squared)
	allOk &= ok

	var nNat, nnNat numct.Nat
	nNat.Mul(p.Factor.Nat(), q.Factor.Nat())
	nnNat.Mul(&nNat, &nNat)

	n, ok := numct.NewModulus(&nNat)
	allOk &= ok
	nn, ok := numct.NewModulus(&nnNat)
	allOk &= ok

	var nModPhiP, nModPhiQ numct.Nat
	p.PhiFactor.Mod(&nModPhiP, &nNat) // n mod (p-1)
	q.PhiFactor.Mod(&nModPhiQ, &nNat) // n mod (q-1)

	// Precompute exponents for direct CRT mod-exp: Ep2 = p * (N mod (p-1)), Eq2 = q * (N mod (q-1))
	var Ep2, Eq2 numct.Nat
	Ep2.Mul(p.Factor.Nat(), &nModPhiP) // p * (q mod (p-1))  since N≡q (mod p-1)
	Eq2.Mul(q.Factor.Nat(), &nModPhiQ) // q * (p mod (q-1))  since N≡p (mod q-1)

	var phiNNat, phiN2Nat numct.Nat
	phiNNat.Mul(p.PhiFactor.Nat(), q.PhiFactor.Nat())
	phiN2Nat.Mul(p.PhiSquared.Nat(), q.PhiSquared.Nat())

	phiN, ok := numct.NewModulus(&phiNNat)
	allOk &= ok
	phiN2, ok := numct.NewModulus(&phiN2Nat)
	allOk &= ok

	return &OddPrimeSquareFactors{
		CrtModN: &OddPrimeFactors{
			Params: crtModN,
			N:      n,
			PhiP:   p.PhiFactor,
			PhiQ:   q.PhiFactor,
			Phi:    phiN,
		},
		CrtModN2: crtModN2,
		P:        p,
		Q:        q,
		N2:       nn,
		NExpP2:   &Ep2,
		NExpQ2:   &Eq2,
		PhiN2:    phiN2,
	}, allOk
}

// OddPrimeSquareFactors implements modular arithmetic modulo n^2 = (p * q)^2,
// where p and q are distinct odd primes.
type OddPrimeSquareFactors struct {
	CrtModN  *OddPrimeFactors    // CRT parameters for p and q
	CrtModN2 *crt.ParamsExtended // CRT parameters for p^2 and q^2
	P        *OddPrimeSquare     // parameters for p
	Q        *OddPrimeSquare     // parameters for q
	N2       *numct.Modulus      // n^2 = (p * q)^2
	NExpP2   *numct.Nat          // Ep2 = p * (N mod (p-1))
	NExpQ2   *numct.Nat          // Eq2 = q * (N mod (q-1))
	PhiN2    *numct.Modulus      // φ(n^2) = φ(p^2)*φ(q^2)
}

// Modulus returns the modulus n^2 = (p * q)^2.
func (m *OddPrimeSquareFactors) Modulus() *numct.Modulus {
	return m.N2
}

// MultiplicativeOrder returns the multiplicative order φ(n^2) = φ(p^2)*φ(q^2).
func (m *OddPrimeSquareFactors) MultiplicativeOrder() algebra.Cardinal {
	return cardinal.NewFromNumeric(m.PhiN2)
}

// ModExp computes out = (base ^ exp) mod n^2.
func (m *OddPrimeSquareFactors) ModExp(out, base, exp *numct.Nat) {
	var mp, mq numct.Nat
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var ep numct.Nat
		m.P.PhiSquared.Mod(&ep, exp)
		// Use reduced exponent when base is coprime (Euler applies),
		// full exponent otherwise.
		ep.Select(base.Coprime(m.P.Factor.Nat()), exp, &ep)
		(m.CrtModN2.P).ModExp(&mp, base, &ep)
	}()
	go func() {
		defer wg.Done()
		var eq numct.Nat
		m.Q.PhiSquared.Mod(&eq, exp)
		eq.Select(base.Coprime(m.Q.Factor.Nat()), exp, &eq)
		m.CrtModN2.Q.ModExp(&mq, base, &eq)
	}()
	wg.Wait()

	out.Set(m.CrtModN2.Recombine(&mp, &mq))
}

// ModExpI computes out = (base ^ exp) mod n^2, where exp is a signed integer.
func (m *OddPrimeSquareFactors) ModExpI(out, base *numct.Nat, exp *numct.Int) {
	var expAbs, out2 numct.Nat
	expAbs.Abs(exp)
	m.ModExp(out, base, &expAbs)
	m.ModInv(&out2, out)
	out.CondAssign(exp.IsNegative(), &out2)
}

// MultiBaseExp computes out[i] = (bases[i] ^ exp) mod n^2 for all i.
func (m *OddPrimeSquareFactors) MultiBaseExp(out, bases []*numct.Nat, exp *numct.Nat) {
	if len(out) != len(bases) {
		panic("out and bases must have the same length")
	}
	k := len(bases)

	var ep, eq numct.Nat
	m.P.PhiSquared.Mod(&ep, exp)
	m.Q.PhiSquared.Mod(&eq, exp)

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
				epi.Select(bi.Coprime(m.P.Factor.Nat()), exp, &ep)
				m.CrtModN2.P.ModExp(&mp, bi, &epi)
			}()
			go func() {
				defer wgInner.Done()
				var eqi numct.Nat
				eqi.Select(bi.Coprime(m.Q.Factor.Nat()), exp, &eq)
				m.CrtModN2.Q.ModExp(&mq, bi, &eqi)
			}()
			wgInner.Wait()
			out[i].Set(m.CrtModN2.Recombine(&mp, &mq))
		}(i)
	}
	wg.Wait()
}

// ModMul computes out = (a * b) mod n^2.
func (m *OddPrimeSquareFactors) ModMul(out, a, b *numct.Nat) {
	m.N2.ModMul(out, a, b)
}

// ModDiv computes out = (a / b) mod n^2.
func (m *OddPrimeSquareFactors) ModDiv(out, a, b *numct.Nat) ct.Bool {
	return m.N2.ModDiv(out, a, b)
}

// ModInv computes out = (a^{-1}) mod n^2.
func (m *OddPrimeSquareFactors) ModInv(out, a *numct.Nat) ct.Bool {
	return m.N2.ModInv(out, a)
}

// ExpToN computes out = (a ^ N) mod n^2 using direct CRT mod-exp.
func (m *OddPrimeSquareFactors) ExpToN(out, a *numct.Nat) {
	// Direct CRT: y_p = a^{Ep2} mod p^2, y_q = a^{Eq2} mod q^2
	var yp, yq numct.Nat
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		m.P.Squared.ModExp(&yp, a, m.NExpP2) //  Ep2 = p * (N mod (p-1))
	}()
	go func() {
		defer wg.Done()
		m.Q.Squared.ModExp(&yq, a, m.NExpQ2) // Eq2 = q * (N mod (q-1))
	}()
	wg.Wait()

	// One-multiply CRT using precomputed (q^2)^{-1} mod p^2 inside m.CrtModN2
	out.Set(m.CrtModN2.Recombine(&yp, &yq))
}
