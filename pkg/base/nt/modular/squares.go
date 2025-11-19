package modular

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/crt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func NewOddPrimeSquare(oddPrimeFactor *numct.Nat) (*OddPrimeSquare, ct.Bool) {
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

type OddPrimeSquare struct {
	Factor     *numct.Modulus
	Squared    *numct.Modulus
	PhiFactor  *numct.Modulus
	PhiSquared *numct.Modulus
}

func (m *OddPrimeSquare) Modulus() *numct.Modulus {
	return m.Squared
}

func (m *OddPrimeSquare) MultiplicativeOrder() algebra.Cardinal {
	return cardinal.NewFromBig(m.PhiSquared.Big())
}

func NewOddPrimeSquareFactors(firstPrime, secondPrime *numct.Nat) (*OddPrimeSquareFactors, ct.Bool) {
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

type OddPrimeSquareFactors struct {
	CrtModN  *OddPrimeFactors
	CrtModN2 *crt.ParamsExtended
	P        *OddPrimeSquare
	Q        *OddPrimeSquare
	N2       *numct.Modulus
	NExpP2   *numct.Nat // Ep2 = p * (N mod (p-1))
	NExpQ2   *numct.Nat // Eq2 = q * (N mod (q-1))
	PhiN2    *numct.Modulus
}

func (m *OddPrimeSquareFactors) Modulus() *numct.Modulus {
	return m.N2
}

func (m *OddPrimeSquareFactors) MultiplicativeOrder() algebra.Cardinal {
	return cardinal.NewFromBig(m.PhiN2.Big())
}

func (m *OddPrimeSquareFactors) ModExp(out, base, exp *numct.Nat) {
	// Compute base^ep mod p and base^eq mod q in parallel.
	var mp, mq numct.Nat
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var ep numct.Nat
		m.P.PhiFactor.Mod(&ep, exp)
		ep.Select(base.Coprime(m.P.Factor.Nat()), exp, &ep)
		(m.CrtModN2.P).ModExp(&mp, base, &ep)
	}()
	go func() {
		defer wg.Done()
		var eq numct.Nat
		m.Q.PhiFactor.Mod(&eq, exp)
		eq.Select(base.Coprime(m.Q.Factor.Nat()), exp, &eq)
		m.CrtModN2.Q.ModExp(&mq, base, &eq)
	}()
	wg.Wait()

	// CRT recombine into modulo n = p*q.
	out.Set(m.CrtModN2.Recombine(&mp, &mq))
}

func (m *OddPrimeSquareFactors) ModExpInt(out, base *numct.Nat, exp *numct.Int) {
	var out2 numct.Nat
	m.ModExp(out, base, exp.AbsNat())
	m.ModInv(&out2, out)
	out.CondAssign(exp.IsNegative(), &out2)
}

func (m *OddPrimeSquareFactors) MultiBaseExp(out []*numct.Nat, bases []*numct.Nat, exp *numct.Nat) {
	if len(out) != len(bases) {
		panic("out and bases must have the same length")
	}
	k := len(bases)

	var ep, eq numct.Nat
	m.P.PhiFactor.Mod(&ep, exp)
	m.Q.PhiFactor.Mod(&eq, exp)

	var wg sync.WaitGroup
	wg.Add(k)
	for i := range k {
		go func(i int) {
			defer wg.Done()
			var mp, mq numct.Nat
			var wgInner sync.WaitGroup
			wgInner.Add(2)
			go func(i int) {
				defer wgInner.Done()
				bi := bases[i]
				var epi numct.Nat
				epi.Select(bi.Coprime(m.P.Factor.Nat()), exp, &ep)
				m.CrtModN2.P.ModExp(&mp, bi, &epi)
			}(i)
			go func(i int) {
				defer wgInner.Done()
				bi := bases[i]
				var eqi numct.Nat
				eqi.Select(bi.Coprime(m.Q.Factor.Nat()), exp, &eq)
				m.CrtModN2.Q.ModExp(&mq, bi, &eqi)
			}(i)
			wgInner.Wait()
			out[i].Set(m.CrtModN2.Recombine(&mp, &mq))
		}(i)
	}
	wg.Wait()
}

func (m *OddPrimeSquareFactors) ModMul(out, a, b *numct.Nat) {
	m.N2.ModMul(out, a, b)
}

func (m *OddPrimeSquareFactors) ModDiv(out, a, b *numct.Nat) ct.Bool {
	return m.N2.ModDiv(out, a, b)
}

func (m *OddPrimeSquareFactors) ModInv(out, a *numct.Nat) ct.Bool {
	return m.N2.ModInv(out, a)
}

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

// func NewOddPrimeSquareFactorsMulti(ps ...*numct.Nat) (*OddPrimeSquareFactorsMulti, ct.Bool) {
// 	factorCount := uint(len(ps))
// 	allOk := ct.Greater(factorCount, 2)

// 	factors := make([]*OddPrimeSquare, factorCount)
// 	p1s := make([]*numct.ModulusOddPrime, factorCount)
// 	p2s := make([]*numct.ModulusOdd, factorCount)
// 	for i, pi := range ps {
// 		factor, ok := NewOddPrimeSquare(pi)
// 		allOk &= ok
// 		factors[i] = factor
// 		p1s[i] = factor.Factor
// 		p2s[i] = factor.Squared
// 	}

// 	crtModP, ok := crt.NewParamsMulti(p1s...)
// 	allOk &= ok

// 	crtModP2, ok := crt.NewParamsMulti(p2s...)
// 	allOk &= ok

// 	// E_i = N mod (p_i - 1)
// 	nModPhis := make([]*numct.Nat, factorCount)
// 	for i, f := range factors {
// 		var ei numct.Nat
// 		f.PhiFactor.Mod(&ei, crtModP.Modulus.Nat()) // phiP is modulus p_i-1
// 		nModPhis[i] = &ei
// 	}

// 	return &OddPrimeSquareFactorsMulti{
// 		CrtModP:  crtModP,
// 		CrtModP2: crtModP2,
// 		Factors:  factors,
// 		NModPhis: nModPhis,
// 	}, ok
// }.

// type OddPrimeSquareFactorsMulti struct {
// 	CrtModP  *crt.ParamsMulti[*numct.ModulusOddPrime]
// 	CrtModP2 *crt.ParamsMulti[*numct.ModulusOdd]
// 	Factors  []*OddPrimeSquare
// 	NModPhis []*numct.Nat
// }.

// func (m *OddPrimeSquareFactorsMulti) Modulus() numct.Modulus {
// 	return m.CrtModP2.Modulus
// }.

// func (m *OddPrimeSquareFactorsMulti) Exp(out, base, exp *numct.Nat) ct.Bool {
// 	residues := make([]*numct.Nat, m.CrtModP.NumFactors)
// 	oks := make([]ct.Bool, m.CrtModP.NumFactors)
// 	var wg sync.WaitGroup
// 	wg.Add(m.CrtModP.NumFactors)
// 	for i := range m.CrtModP.NumFactors {
// 		go func(i int) {
// 			defer wg.Done()
// 			var ri numct.Nat
// 			oks[i] = m.Factors[i].Exp(&ri, base, exp)
// 			residues[i] = &ri
// 		}(i)
// 	}
// 	wg.Wait()
// 	res, ok := m.CrtModP2.Recombine(residues...)
// 	out.Set(res)
// 	for _, oki := range oks {
// 		ok &= oki
// 	}
// 	return ok
// }.

// // ExpToN computes a^N mod N^2 using one mod-p^2 exponent per prime.
// // If a ≡ 0 mod p_i for any factor, the residue is 0 for that i and ok becomes ct.False.
// // All per-prime steps run in parallel; no calls into Decompose/Exp.
// func (m *OddPrimeSquareFactorsMulti) ExpToN(out, a *numct.Nat) ct.Bool {
// 	k := m.CrtModP2.NumFactors
// 	residues := make([]*numct.Nat, k)
// 	unitOK := make([]ct.Bool, k)

// 	var wg sync.WaitGroup
// 	wg.Add(k)
// 	for i := range k {
// 		go func(i int) {
// 			defer wg.Done()
// 			fi := m.Factors[i]

// 			// a0 = a mod p_i
// 			var a0 numct.Nat
// 			fi.Factor.Mod(&a0, a)
// 			isZero := a0.IsZero() // ct.Bool

// 			// b = a0^(E_i) mod p_i  (E_i precomputed)
// 			var b numct.Nat
// 			ei := m.NModPhis[i]
// 			fi.Factor.ModExp(&b, &a0, ei)

// 			// riUnit = b^p_i mod p_i^2  (Teichmüller lift ω(b))
// 			var riUnit, ri, z numct.Nat
// 			fi.Squared.ModExp(&riUnit, &b, fi.FactorNat)
// 			z.SetZero()

// 			// ri = isZero ? 0 : riUnit  (Select(cond, onFalse, onTrue))
// 			ri.Select(isZero, &z, &riUnit)
// 			residues[i] = &ri

// 			unitOK[i] = isZero.Not()
// 		}(i)
// 	}
// 	wg.Wait()

// 	r, crtOK := m.CrtModP2.Recombine(residues...)
// 	out.Set(r)

// 	ok := crtOK
// 	for i := range k {
// 		ok &= unitOK[i]
// 	}
// 	return ok
// }.
