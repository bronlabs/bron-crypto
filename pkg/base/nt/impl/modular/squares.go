package modular

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl/crt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
)

func NewOddPrimeSquareFactorSingle[M internal.ModulusMutablePtr[N, MT], MO internal.ModulusMutablePtr[N, MOT], MOP internal.ModulusMutablePtr[N, MOPT], N internal.NatMutablePtr[N, NT], MT, MOT, MOPT, NT any](
	oddPrimeFactor N,
) (*OddPrimeSquareFactorSingle[M, MO, MOP, N, MT, MOT, MOPT, NT], ct.Bool) {
	ok := oddPrimeFactor.IsProbablyPrime() & oddPrimeFactor.IsOdd()

	var p MOPT
	ok &= MOP(&p).SetNat(oddPrimeFactor.Clone())

	var phiPNat, phiP2Nat NT
	N(&phiPNat).Set(oddPrimeFactor.Clone())
	N(&phiPNat).Decrement()                       // φ(p) = p - 1
	N(&phiP2Nat).Mul(N(&phiPNat), oddPrimeFactor) // φ(p^2) = p^2 - p = p * (p - 1)

	var phiP, phiP2 MT
	M(&phiP).SetNat(N(&phiPNat))
	M(&phiP2).SetNat(N(&phiP2Nat))

	var p2Nat NT
	N(&p2Nat).Mul(oddPrimeFactor, oddPrimeFactor) // p^2
	var p2 MOT
	ok &= MO(&p2).SetNat(N(&p2Nat))

	return &OddPrimeSquareFactorSingle[M, MO, MOP, N, MT, MOT, MOPT, NT]{
		p:     MOP(&p),
		pNat:  oddPrimeFactor.Clone(),
		p2:    MO(&p2),
		phiP:  M(&phiP),
		phiP2: M(&phiP2),
	}, ok

}

type OddPrimeSquareFactorSingle[M internal.ModulusMutablePtr[N, MT], MO internal.ModulusMutablePtr[N, MOT], MOP internal.ModulusMutablePtr[N, MOPT], N internal.NatMutablePtr[N, NT], MT, MOT, MOPT, NT any] struct {
	p     MOP
	pNat  N
	p2    MO
	phiP  M
	phiP2 M
}

func (m *OddPrimeSquareFactorSingle[M, MO, MOP, N, MT, MOT, MOPT, NT]) Modulus() MO {
	return m.p2
}

// Computes a^e mod p^2 (odd prime p) with a constant-time code path.
// It handles all a (units and non-units) and any non-negative e.
func (m *OddPrimeSquareFactorSingle[M, MO, MOP, N, MT, MOT, MOPT, NT]) Exp(out N, a, e N) (ok ct.Bool) {
	var zero, one NT
	N(&zero).SetZero()
	N(&one).SetOne()

	// Decompose: vp ∈ {0,1,2}; w = Teich; u = principal unit = 1 + p*t
	var w, t, u NT
	vp := m.Decompose(N(&w), N(&t), N(&u), a)

	// w-part: w^(e mod (p-1)) mod p^2
	var eModPhi, wPow NT
	m.phiP.Mod(N(&eModPhi), e) // e mod (p-1)
	m.p2.ModExp(N(&wPow), N(&w), N(&eModPhi))

	// u-part: (1 + p*t)^e ≡ 1 + (e mod p)*(u - 1)  (mod p^2)
	var eModP, uMinus1, uPart NT
	m.p.Mod(N(&eModP), e)  // e mod p
	N(&uMinus1).Set(N(&u)) // u - 1
	N(&uMinus1).Decrement()

	m.p2.ModMul(N(&uPart), N(&eModP), N(&uMinus1)) // (e mod p)*(u-1) mod p^2
	m.p2.ModAdd(N(&uPart), N(&uPart), N(&one))     // +1 mod p^2

	// Candidate outputs for m in {0,1,2}
	// vp==0 (unit): w^e * (1 + p*(e mod p)*t)
	vIsZero := ct.Equal(uint(vp), 0)
	var out0 NT
	m.p2.ModMul(N(&out0), N(&wPow), N(&uPart)) // w^e * u

	// vp==1 branch:
	// if e==1: out1 = p * w; else out1 = 0
	vIsOne := ct.Equal(uint(vp), 1)
	var out1, pTimesW NT
	m.p2.ModMul(N(&pTimesW), m.pNat, N(&w))                         // p * w
	N(&out1).Select(N(e).Equal(N(&one)), N(&zero), N(&pTimesW)) // if e==1 -> p*w else 0

	// m==2: always 0 for e>0; we'll mask later with e==0 override.
	vIsTwo := ct.Equal(uint(vp), 2)
	out2 := N(&zero).Clone()

	// Select by v (branchless)
	var tmp NT
	N(&tmp).Select(vIsOne, N(&out0), N(&out1))
	out.Select(vIsTwo, N(&tmp), out2)

	// e==0 override: a^0 == 1 mod p^2
	condEIsZero := ct.Equal(e.Uint64(), 0)
	out.Select(condEIsZero, out, N(&one))
	return vIsZero | vIsOne | vIsTwo
}

// DecomposePrimeSquareCT computes (m, w, t) for a mod p^2 with odd prime p,
// in a branchless style.
// - m = min(v_p(a), 2)
// - w = Teichmüller lift of the unit part modulo p^2 (set to 1 if m=2)
// - t ∈ Z/pZ with a ≡ p^m * w * (1 + p t) (mod p^2), and t = 0 if m=2.
// - u1 = 1 + p t (the principal unit), forced to 1 if m=2.
func (mo *OddPrimeSquareFactorSingle[M, MO, MOP, N, MT, MOT, MOPT, NT]) Decompose(outW, outT, outU N, a N) (m int) {
	var zero, one NT
	N(&zero).SetZero()
	N(&one).SetOne()

	// aMod in [0, p^2)
	var aMod NT
	mo.p2.Mod(N(&aMod), a)

	// m ∈ {0,1,2}; u = a / p^m  (mod p^2)
	var u NT
	m = impl.Vp(N(&u), mo.p, N(&aMod), 2)
	mIs2 := ct.Equal(uint(m), 2)

	// a0 = u mod p (∈ F_p^× for m∈{0,1}, arbitrary for m=2 -> we later mask)
	var a0 NT
	mo.p.Mod(N(&a0), N(&u))

	// Teichmüller for k=2: w = a0^p mod p^2
	var wCalc NT
	mo.p2.ModExp(N(&wCalc), N(&a0), mo.pNat)
	// If m==2, force w=1
	outW.Select(mIs2, N(&wCalc), N(&one))

	// q = u * w^{-1} (mod p^2)  == principal unit 1 + p t
	var q, wInv NT
	mo.p2.ModInv(N(&wInv), outW)
	mo.p2.ModMul(N(&q), N(&u), N(&wInv))
	// u1 = q; if m==2, force u1 = 1
	outU.Select(mIs2, N(&q), N(&one))

	// t = ((q - 1)/p) (exact) in Z/pZ; if m==2, force t=0
	var qm1 NT
	N(&qm1).Set(N(&q))
	N(&qm1).Decrement()         // q - 1
	mo.p2.Mod(N(&qm1), N(&qm1)) // canonicalize
	// Exact integer division: (q-1) / p
	// Since q = 1 + p*t, we have q-1 = p*t, so this division is exact
	mo.p.Quo(outT, N(&qm1)) // exact division by p
	outT.Select(mIs2, outT, N(&zero))

	return m
}

func NewOddPrimeSquareFactorsMulti[M internal.ModulusMutablePtr[N, MT], MO internal.ModulusMutablePtr[N, MOT], MOP internal.ModulusMutablePtr[N, MOPT], N internal.NatMutablePtr[N, NT], MT, MOT, MOPT, NT any](
	ps ...N,
) (*OddPrimeSquareFactorsMulti[M, MO, MOP, N, MT, MOT, MOPT, NT], ct.Bool) {
	factorCount := uint(len(ps))
	allOk := ct.Greater(factorCount, 0)

	factors := make([]*OddPrimeSquareFactorSingle[M, MO, MOP, N, MT, MOT, MOPT, NT], factorCount)
	p2s := make([]N, factorCount)
	for i, pi := range ps {
		factor, ok := NewOddPrimeSquareFactorSingle[M, MO, MOP](pi)
		allOk &= ok
		factors[i] = factor
		p2s[i] = factor.p2.Nat()
	}

	crtModP, ok := crt.Precompute[MO, MOP](ps...)
	allOk &= ok

	crtModP2, ok := crt.Precompute[MO, MO](p2s...)
	allOk &= ok

	// E_i = N mod (p_i - 1)
	nModPhis := make([]N, factorCount)
	for i, f := range factors {
		var ei NT
		f.phiP.Mod(N(&ei), crtModP.Modulus.Nat()) // phiP is modulus p_i-1
		nModPhis[i] = N(&ei)
	}

	return &OddPrimeSquareFactorsMulti[M, MO, MOP, N, MT, MOT, MOPT, NT]{
		crtModP:  crtModP,
		crtModP2: crtModP2,
		factors:  factors,
		nModPhis: nModPhis,
	}, ok
}

type OddPrimeSquareFactorsMulti[M internal.ModulusMutablePtr[N, MT], MO internal.ModulusMutablePtr[N, MOT], MOP internal.ModulusMutablePtr[N, MOPT], N internal.NatMutablePtr[N, NT], MT, MOT, MOPT, NT any] struct {
	crtModP  *crt.Params[MO, MOP, N, MOT, MOPT, NT]
	crtModP2 *crt.Params[MO, MO, N, MOT, MOT, NT]
	factors  []*OddPrimeSquareFactorSingle[M, MO, MOP, N, MT, MOT, MOPT, NT]
	nModPhis []N
}

func (m *OddPrimeSquareFactorsMulti[M, MO, MOP, N, MT, MOT, MOPT, NT]) Modulus() MO {
	return m.crtModP2.Modulus
}

func (m *OddPrimeSquareFactorsMulti[M, MO, MOP, N, MT, MOT, MOPT, NT]) Exp(out, base, exp N) ct.Bool {
	residues := make([]N, m.crtModP.NumFactors)
	oks := make([]ct.Bool, m.crtModP.NumFactors)
	var wg sync.WaitGroup
	wg.Add(m.crtModP.NumFactors)
	for i := range m.crtModP.NumFactors {
		go func(i int) {
			defer wg.Done()
			var ri NT
			oks[i] = m.factors[i].Exp(N(&ri), base, exp)
			residues[i] = N(&ri)
		}(i)
	}
	wg.Wait()
	res, ok := m.crtModP2.Recombine(residues)
	out.Set(res)
	for _, oki := range oks {
		ok &= oki
	}
	return ok
}

// ExpToN computes a^N mod N^2 using one mod-p^2 exponent per prime.
// If a ≡ 0 mod p_i for any factor, the residue is 0 for that i and ok becomes ct.False.
// All per-prime steps run in parallel; no calls into Decompose/Exp.
func (m *OddPrimeSquareFactorsMulti[M, MO, MOP, N, MT, MOT, MOPT, NT]) ExpToN(out, a N) ct.Bool {
	k := m.crtModP2.NumFactors
	residues := make([]N, k)
	unitOK := make([]ct.Bool, k)

	var wg sync.WaitGroup
	wg.Add(k)
	for i := 0; i < k; i++ {
		go func(i int) {
			defer wg.Done()
			fi := m.factors[i]

			// a0 = a mod p_i
			var a0 NT
			fi.p.Mod(N(&a0), a)
			isZero := N(&a0).IsZero() // ct.Bool

			// b = a0^(E_i) mod p_i  (E_i precomputed)
			var ei, b NT
			N(&ei).Set((m.nModPhis[i]))
			fi.p.ModExp(N(&b), N(&a0), N(&ei))

			// riUnit = b^p_i mod p_i^2  (Teichmüller lift ω(b))
			var riUnit, ri, z NT
			fi.p2.ModExp(N(&riUnit), N(&b), fi.pNat)
			N(&z).SetZero()

			// ri = isZero ? 0 : riUnit   (your Select is "backwards")
			N(&ri).Select(isZero, N(&riUnit), N(&z))
			residues[i] = N(&ri)

			unitOK[i] = isZero.Not() // ok flag: true iff a0 ≠ 0
		}(i)
	}
	wg.Wait()

	r, crtOK := m.crtModP2.Recombine(residues)
	out.Set(r)

	ok := crtOK
	for i := range k {
		ok &= unitOK[i]
	}
	return ok
}
