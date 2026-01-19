package crt

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// ParamsMulti holds precomputed values for multi-factor CRT with k pairwise coprime factors.
// For factors p_1, p_2, ..., p_k, we precompute:
// - M_i = N / p_i where N = p_1 * p_2 * ... * p_k
// - M_i^{-1} mod p_i for each i.
type ParamsMulti struct {
	Factors    []*numct.Modulus // p_i as moduli
	Products   []*numct.Nat     // M_i = N / p_i
	Inverses   []*numct.Nat     // inv_i = (M_i)^{-1} mod p_i
	Lifts      []*numct.Nat     // Lift_i = M_i * inv_i mod N
	Modulus    *numct.Modulus   // N as a modulus object (for Mod reductions)
	NumFactors int              // number of factors (pairwise coprime, not necessarily prime)
	// Garner's algorithm precomputed values:
	// GarnerCoeffs[i][j] = (p_1 * ... * p_j)^{-1} mod p_{i+1} for j < i
	GarnerCoeffs [][]*numct.Nat
}

// NewParamsMulti constructs multi-factor CRT parameters from given moduli.
func NewParamsMulti(factors ...*numct.Modulus) (params *ParamsMulti, ok ct.Bool) {
	k := len(factors)
	allOk := ct.GreaterOrEqual(k, 2)

	params = &ParamsMulti{
		Factors:      make([]*numct.Modulus, k),
		Products:     make([]*numct.Nat, k),
		Inverses:     make([]*numct.Nat, k),
		Lifts:        make([]*numct.Nat, k),
		NumFactors:   k,
		GarnerCoeffs: make([][]*numct.Nat, k),
		Modulus:      nil,
	}

	// Set p_i as moduli and compute N = ∏ p_i
	prod := numct.NatOne()
	for i := range k {
		params.Factors[i] = factors[i]
		capMul := prod.AnnouncedLen() + factors[i].BitLen()
		prod.MulCap(prod, factors[i].Nat(), capMul)
	}
	modulus, ok := numct.NewModulus(prod)
	allOk &= ok
	params.Modulus = modulus

	// For each i: M_i = N / p_i; inv_i = (M_i)^{-1} mod p_i; Lift_i = M_i * inv_i mod N
	var Mi, MiModPi, inv, lift numct.Nat
	for i := range k {
		// M_i = N / p_i
		allOk &= Mi.Div(nil, prod, factors[i].Nat())
		params.Products[i] = Mi.Clone()

		// inv_i = (M_i mod p_i)^{-1} mod p_i  (ok iff gcd(M_i, p_i)=1)
		params.Factors[i].Mod(&MiModPi, &Mi)

		allOk &= params.Factors[i].ModInv(&inv, &MiModPi)
		params.Inverses[i] = inv.Clone()

		// Lift_i = (M_i * inv_i) mod N
		capMul := Mi.AnnouncedLen() + inv.AnnouncedLen()
		lift.MulCap(&Mi, &inv, capMul)
		params.Modulus.Mod(&lift, &lift)
		params.Lifts[i] = lift.Clone()
	}

	// Precompute Garner coefficients
	// For each p_i (i >= 1), we need inverses of P_j mod p_i for all j < i
	// where P_j = p_0 * p_1 * ... * p_j
	for i := 1; i < k; i++ {
		params.GarnerCoeffs[i] = make([]*numct.Nat, i)

		// Compute P_j for j = 0 to i-1
		pProd := numct.NatOne()
		for j := range i {
			// pProd = p_0 * ... * p_j
			capMul := pProd.AnnouncedLen() + factors[j].BitLen()
			pProd.MulCap(pProd, factors[j].Nat(), capMul)

			// Compute pProd^{-1} mod p_i
			var pProdModPi, inv numct.Nat
			params.Factors[i].Mod(&pProdModPi, pProd)
			allOk &= params.Factors[i].ModInv(&inv, &pProdModPi)
			params.GarnerCoeffs[i][j] = inv.Clone()
		}
	}

	return params, allOk
}

// PrecomputeMulti precomputes CRT parameters for k primes.
// All operations are constant-time with respect to the prime values.
// Returns nil if any prime is not coprime to the others.
func PrecomputeMulti(factors ...*numct.Nat) (params *ParamsMulti, ok ct.Bool) {
	allOk := ct.True
	fs := make([]*numct.Modulus, len(factors))
	for i, f := range factors {
		fi, ok := numct.NewModulus(f)
		allOk &= ok
		fs[i] = fi
	}
	out, ok := NewParamsMulti(fs...)
	allOk &= ok
	return out, allOk
}

// RecombineParallel reconstructs x (mod N) from residues[i] = x mod p_i using precomputed lifts.
// x ≡ Σ residues[i] * Lift_i (mod N).
func (prm *ParamsMulti) RecombineParallel(residues ...*numct.Nat) (result *numct.Nat, ok ct.Bool) {
	eqLen := ct.Equal(len(residues), prm.NumFactors)
	if eqLen == ct.False {
		return nil, eqLen
	}
	var wg sync.WaitGroup
	wg.Add(prm.NumFactors)

	terms := make([]*numct.Nat, prm.NumFactors)
	for i := range prm.NumFactors {
		go func(idx int) {
			defer wg.Done()
			var term numct.Nat
			prm.Modulus.ModMul(&term, residues[idx], prm.Lifts[idx])
			terms[idx] = &term
		}(i)
	}
	wg.Wait()
	result = numct.NatZero()
	for i := range terms {
		prm.Modulus.ModAdd(result, result, terms[i])
	}
	return result, eqLen
}

// RecombineSerial reconstructs x (mod N) from residues[i] = x mod p_i using Garner's algorithm.
func (prm *ParamsMulti) RecombineSerial(residues ...*numct.Nat) (result *numct.Nat, ok ct.Bool) {
	eqLen := ct.Equal(len(residues), prm.NumFactors)
	if eqLen == ct.False {
		return nil, eqLen
	}
	// Garner's algorithm:
	// Start with x = a_0
	// For i = 1 to k-1:
	//   c_i = (a_i - x) * (p_0 * ... * p_{i-1})^{-1} mod p_i
	//   x = x + c_i * (p_0 * ... * p_{i-1})

	result = residues[0].Clone() // x = a_0
	pProd := numct.NatOne()
	for i := 1; i < prm.NumFactors; i++ {
		// Update pProd = p_0 * ... * p_{i-1}
		capMul := pProd.AnnouncedLen() + prm.Factors[i-1].Nat().AnnouncedLen()
		(pProd).MulCap(pProd, prm.Factors[i-1].Nat(), capMul)

		// Compute c_i = (a_i - x) * (p_0 * ... * p_{i-1})^{-1} mod p_i
		var xModPi, diff, ci numct.Nat
		prm.Factors[i].Mod(&xModPi, result)
		prm.Factors[i].ModSub(&diff, residues[i], &xModPi)
		prm.Factors[i].ModMul(&ci, &diff, prm.GarnerCoeffs[i][i-1])

		// x = x + c_i * pProd
		var term numct.Nat
		capMul = ci.AnnouncedLen() + pProd.AnnouncedLen()
		term.MulCap(&ci, pProd, capMul)
		capAdd := result.AnnouncedLen() + term.AnnouncedLen()
		result.AddCap(result, &term, capAdd)
	}

	// Clone to return a properly typed value
	return result, eqLen
}

// Recombine reconstructs x (mod N) from residues[i] = x mod p_i.
// Recombine chooses between serial and parallel based on size.
// The choice is deterministic based on modulus size and prime count.
func (prm *ParamsMulti) Recombine(residues ...*numct.Nat) (result *numct.Nat, ok ct.Bool) {
	if prm.NumFactors <= 4 {
		return prm.RecombineSerial(residues...)
	}
	return prm.RecombineParallel(residues...)
}

// DecomposeSerial decomposes m into residues mod each prime.
// Constant-time with respect to values (not the number of primes).
func (prm *ParamsMulti) DecomposeSerial(m *numct.Modulus) []*numct.Nat {
	residues := make([]*numct.Nat, prm.NumFactors)

	// Process all primes to maintain constant time
	for i := range prm.NumFactors {
		var residueT numct.Nat
		prm.Factors[i].Mod(&residueT, m.Nat())
		residues[i] = &residueT
	}

	return residues
}

// DecomposeParallel decomposes m into residues mod each prime in parallel.
// Constant-time with respect to values (not the number of primes).
func (prm *ParamsMulti) DecomposeParallel(m *numct.Modulus) []*numct.Nat {
	residues := make([]*numct.Nat, prm.NumFactors)

	var wg sync.WaitGroup
	wg.Add(prm.NumFactors)

	// Launch all goroutines to maintain constant time
	for i := range prm.NumFactors {
		go func(idx int) {
			defer wg.Done()
			var residue numct.Nat
			prm.Factors[idx].Mod(&residue, m.Nat())
			residues[idx] = &residue
		}(i)
	}

	wg.Wait()
	return residues
}

// Decompose chooses between serial and parallel based on size.
// The choice is deterministic based on modulus size and prime count.
func (prm *ParamsMulti) Decompose(m *numct.Modulus) []*numct.Nat {
	// Use parallel for larger moduli or more primes
	// This is a deterministic choice, not data-dependent
	if m.BitLen() > 4096 || prm.NumFactors > 3 {
		return prm.DecomposeParallel(m)
	}
	return prm.DecomposeSerial(m)
}
