package crt

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// ParamsMulti holds precomputed values for multi-factor CRT with k pairwise coprime factors.
// For factors p_1, p_2, ..., p_k, we precompute:
// - M_i = N / p_i where N = p_1 * p_2 * ... * p_k
// - M_i^{-1} mod p_i for each i
type ParamsMulti[F numct.Modulus] struct {
	Factors    []F           // p_i as moduli
	Products   []*numct.Nat  // M_i = N / p_i
	Inverses   []*numct.Nat  // inv_i = (M_i)^{-1} mod p_i
	Lifts      []*numct.Nat  // Lift_i = M_i * inv_i mod N
	Modulus    numct.Modulus // N as a modulus object (for Mod reductions)
	NumFactors int           // number of factors (pairwise coprime, not necessarily prime)
	// Garner's algorithm precomputed values:
	// GarnerCoeffs[i][j] = (p_1 * ... * p_j)^{-1} mod p_{i+1} for j < i
	GarnerCoeffs [][]*numct.Nat
}

func NewParamsMulti[F numct.Modulus](factors ...F) (*ParamsMulti[F], ct.Bool) {
	k := len(factors)
	allOk := ct.GreaterOrEqual(k, 2)

	params := &ParamsMulti[F]{
		Factors:      make([]F, k),
		Products:     make([]*numct.Nat, k),
		Inverses:     make([]*numct.Nat, k),
		Lifts:        make([]*numct.Nat, k),
		NumFactors:   k,
		GarnerCoeffs: make([][]*numct.Nat, k),
	}

	// Set p_i as moduli and compute N = ∏ p_i
	prod := numct.NatOne()
	for i := range k {
		params.Factors[i] = factors[i]
		capMul := int(prod.AnnouncedLen() + factors[i].BitLen())
		prod.MulCap(prod, factors[i].Nat(), capMul)
	}
	modulus, ok := numct.NewModulus(prod)
	allOk &= ok
	params.Modulus = modulus

	// For each i: M_i = N / p_i; inv_i = (M_i)^{-1} mod p_i; Lift_i = M_i * inv_i mod N
	var Mi, MiModPi, inv, lift numct.Nat
	divCap := int(modulus.BitLen())
	for i := range k {
		// M_i = N / p_i
		allOk &= Mi.DivCap(prod, factors[i], divCap)
		params.Products[i] = Mi.Clone()

		// inv_i = (M_i mod p_i)^{-1} mod p_i  (ok iff gcd(M_i, p_i)=1)
		params.Factors[i].Mod(&MiModPi, &Mi)

		allOk &= params.Factors[i].ModInv(&inv, &MiModPi)
		params.Inverses[i] = inv.Clone()

		// Lift_i = (M_i * inv_i) mod N
		capMul := int(Mi.AnnouncedLen() + inv.AnnouncedLen())
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
			capMul := int(pProd.AnnouncedLen() + factors[j].BitLen())
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
func PrecomputeMulti[F numct.Modulus](factors ...*numct.Nat) (*ParamsMulti[F], ct.Bool) {
	allOk := ct.True
	var okT bool
	fs := make([]F, len(factors))
	for i, f := range factors {
		fi, ok := numct.NewModulus(f)
		allOk &= ok
		fs[i], okT = fi.(F)
		allOk &= utils.BoolTo[ct.Bool](okT)
	}
	out, ok := NewParamsMulti(fs...)
	allOk &= ok
	return out, allOk
}

// RecombineParallel reconstructs x (mod N) from residues[i] = x mod p_i using precomputed lifts.
// x ≡ Σ residues[i] * Lift_i (mod N)
func (params *ParamsMulti[F]) RecombineParallel(residues ...*numct.Nat) *numct.Nat {
	var wg sync.WaitGroup
	wg.Add(params.NumFactors)

	terms := make([]*numct.Nat, params.NumFactors)
	for i := range params.NumFactors {
		go func(idx int) {
			defer wg.Done()
			var term numct.Nat
			params.Modulus.ModMul(&term, residues[idx], params.Lifts[idx])
			terms[idx] = &term
		}(i)
	}
	wg.Wait()
	result := numct.NatZero()
	for i := range terms {
		params.Modulus.ModAdd(result, result, terms[i])
	}
	return result
}

// Recombine reconstructs x (mod N) from residues[i] = x mod p_i using Garner's algorithm.
func (params *ParamsMulti[F]) RecombineSerial(residues ...*numct.Nat) *numct.Nat {
	// Garner's algorithm:
	// Start with x = a_0
	// For i = 1 to k-1:
	//   c_i = (a_i - x) * (p_0 * ... * p_{i-1})^{-1} mod p_i
	//   x = x + c_i * (p_0 * ... * p_{i-1})

	result := residues[0].Clone() // x = a_0
	pProd := numct.NatOne()
	for i := 1; i < params.NumFactors; i++ {
		// Update pProd = p_0 * ... * p_{i-1}
		capMul := int(pProd.AnnouncedLen() + params.Factors[i-1].Nat().AnnouncedLen())
		(pProd).MulCap(pProd, params.Factors[i-1].Nat(), capMul)

		// Compute c_i = (a_i - x) * (p_0 * ... * p_{i-1})^{-1} mod p_i
		var xModPi, diff, ci numct.Nat
		params.Factors[i].Mod(&xModPi, result)
		params.Factors[i].ModSub(&diff, residues[i], &xModPi)
		params.Factors[i].ModMul(&ci, &diff, params.GarnerCoeffs[i][i-1])

		// x = x + c_i * pProd
		var term numct.Nat
		capMul = int(term.AnnouncedLen() + pProd.AnnouncedLen())
		term.MulCap(&ci, pProd, capMul)
		capAdd := int(result.AnnouncedLen() + term.AnnouncedLen())
		result.AddCap(result, &term, capAdd)
	}

	// Clone to return a properly typed value
	return result
}

func (params *ParamsMulti[F]) Recombine(residues ...*numct.Nat) (*numct.Nat, ct.Bool) {
	eqLen := ct.Equal(len(residues), params.NumFactors)
	if params.NumFactors <= 4 {
		return params.RecombineSerial(residues...), eqLen
	}
	return params.RecombineParallel(residues...), eqLen
}

// DecomposeMultiSerial decomposes m into residues mod each prime.
// Constant-time with respect to values (not the number of primes).
func (params *ParamsMulti[F]) DecomposeSerial(m *numct.ModulusOdd) []*numct.Nat {
	residues := make([]*numct.Nat, params.NumFactors)

	// Process all primes to maintain constant time
	for i := range params.NumFactors {
		var residueT numct.Nat
		params.Factors[i].Mod(&residueT, m.Nat())
		residues[i] = &residueT
	}

	return residues
}

// DecomposeMultiParallel decomposes m into residues mod each prime in parallel.
// Constant-time with respect to values (not the number of primes).
func (params *ParamsMulti[F]) DecomposeParallel(m *numct.ModulusOdd) []*numct.Nat {
	residues := make([]*numct.Nat, params.NumFactors)

	var wg sync.WaitGroup
	wg.Add(params.NumFactors)

	// Launch all goroutines to maintain constant time
	for i := range params.NumFactors {
		go func(idx int) {
			defer wg.Done()
			params.Factors[idx].Mod(residues[idx], m.Nat())
		}(i)
	}

	wg.Wait()
	return residues
}

// Decompose chooses between serial and parallel based on size.
// The choice is deterministic based on modulus size and prime count.
func (params *ParamsMulti[F]) Decompose(m *numct.ModulusOdd) []*numct.Nat {
	// Use parallel for larger moduli or more primes
	// This is a deterministic choice, not data-dependent
	if m.BitLen() > 4096 || params.NumFactors > 3 {
		return params.DecomposeParallel(m)
	}
	return params.DecomposeSerial(m)
}
