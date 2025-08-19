package crt

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// Params holds precomputed values for multi-factor CRT with k pairwise coprime factors.
// For factors p_1, p_2, ..., p_k, we precompute:
// - M_i = N / p_i where N = p_1 * p_2 * ... * p_k
// - M_i^{-1} mod p_i for each i
type Params[MM internal.ModulusMutablePtr[N, MMT], MF internal.ModulusMutablePtr[N, MFT], N internal.NatMutablePtr[N, NT], MMT, MFT, NT any] struct {
	Factors    []MF // p_i as moduli
	Products   []N  // M_i = N / p_i
	Inverses   []N  // inv_i = (M_i)^{-1} mod p_i
	Lifts      []N  // Lift_i = M_i * inv_i mod N
	Modulus    MM   // N as a modulus object (for Mod reductions)
	NumFactors int  // number of factors (pairwise coprime, not necessarily prime)
	// Garner's algorithm precomputed values:
	// GarnerCoeffs[i][j] = (p_1 * ... * p_j)^{-1} mod p_{i+1} for j < i
	GarnerCoeffs [][]N
}

// Precompute precomputes CRT parameters for k primes.
// All operations are constant-time with respect to the prime values.
// Returns nil if any prime is not coprime to the others.
func Precompute[MM internal.ModulusMutablePtr[N, MMT], MF internal.ModulusMutablePtr[N, MFT], N internal.NatMutablePtr[N, NT], MMT, MFT, NT any](
	factors ...N,
) (*Params[MM, MF, N, MMT, MFT, NT], ct.Bool) {
	k := len(factors)
	allOk := utils.BoolTo[ct.Bool](k >= 2)

	params := &Params[MM, MF, N, MMT, MFT, NT]{
		Factors:      make([]MF, k),
		Products:     make([]N, k),
		Inverses:     make([]N, k),
		Lifts:        make([]N, k),
		NumFactors:   k,
		GarnerCoeffs: make([][]N, k),
	}

	// Set p_i as moduli and compute N = ∏ p_i
	var prod NT
	N(&prod).SetOne()
	for i := range k {
		var factorI MFT
		allOk &= MF(&factorI).SetNat(factors[i])
		params.Factors[i] = MF(&factorI)
		capMul := algebra.Capacity(N(&prod).AnnouncedLen() + factors[i].AnnouncedLen())
		N(&prod).MulCap(N(&prod), factors[i], capMul)
	}
	var modulus MMT
	allOk &= MM(&modulus).SetNat(N(&prod))
	params.Modulus = MM(&modulus)

	// For each i: M_i = N / p_i; inv_i = (M_i)^{-1} mod p_i; Lift_i = M_i * inv_i mod N
	var Mi, MiModPi, inv, lift NT
	for i := range k {
		// M_i = N / p_i
		divCap := algebra.Capacity(MM(&modulus).BitLen())
		allOk &= N(&Mi).DivCap(N(&prod), factors[i], divCap)
		params.Products[i] = N(&Mi).Clone()

		// inv_i = (M_i mod p_i)^{-1} mod p_i  (ok iff gcd(M_i, p_i)=1)
		params.Factors[i].Mod(N(&MiModPi), N(&Mi))

		allOk &= params.Factors[i].ModInv(N(&inv), N(&MiModPi))
		params.Inverses[i] = N(&inv).Clone()

		// Lift_i = (M_i * inv_i) mod N
		capMul := algebra.Capacity(N(&Mi).AnnouncedLen() + N(&inv).AnnouncedLen())
		N(&lift).MulCap(N(&Mi), N(&inv), capMul)
		params.Modulus.Mod(N(&lift), N(&lift))
		params.Lifts[i] = N(&lift).Clone()
	}

	// Precompute Garner coefficients
	// For each p_i (i >= 1), we need inverses of P_j mod p_i for all j < i
	// where P_j = p_0 * p_1 * ... * p_j
	for i := 1; i < k; i++ {
		params.GarnerCoeffs[i] = make([]N, i)

		// Compute P_j for j = 0 to i-1
		var pProd NT
		N(&pProd).SetOne()
		for j := 0; j < i; j++ {
			// pProd = p_0 * ... * p_j
			capMul := algebra.Capacity(N(&pProd).AnnouncedLen() + factors[j].AnnouncedLen())
			N(&pProd).MulCap(N(&pProd), factors[j], capMul)

			// Compute pProd^{-1} mod p_i
			var pProdModPi, inv NT
			params.Factors[i].Mod(N(&pProdModPi), N(&pProd))
			allOk &= params.Factors[i].ModInv(N(&inv), N(&pProdModPi))
			params.GarnerCoeffs[i][j] = N(&inv).Clone()
		}
	}

	return params, allOk
}

// RecombineParallel reconstructs x (mod N) from residues[i] = x mod p_i using precomputed lifts.
// x ≡ Σ residues[i] * Lift_i (mod N)
func (params *Params[MM, MF, N, MMT, MFT, NT]) RecombineParallel(residues []N) (N, ct.Bool) {
	allOk := utils.BoolTo[ct.Bool](len(residues) == params.NumFactors)

	var wg sync.WaitGroup
	wg.Add(params.NumFactors)

	terms := make([]N, params.NumFactors)
	for i := range params.NumFactors {
		go func(idx int) {
			defer wg.Done()
			var term NT
			params.Modulus.ModMul(N(&term), residues[idx], params.Lifts[idx])
			terms[idx] = N(&term)
		}(i)
	}
	wg.Wait()
	var result NT
	N(&result).SetZero()
	for i := range terms {
		params.Modulus.ModAdd(N(&result), N(&result), terms[i])
	}
	return N(&result), allOk
}

// Recombine reconstructs x (mod N) from residues[i] = x mod p_i using Garner's algorithm.
func (params *Params[MM, MF, N, MMT, MFT, NT]) Recombine(residues []N) (N, ct.Bool) {
	allOk := utils.BoolTo[ct.Bool](len(residues) == params.NumFactors)

	// Garner's algorithm:
	// Start with x = a_0
	// For i = 1 to k-1:
	//   c_i = (a_i - x) * (p_0 * ... * p_{i-1})^{-1} mod p_i
	//   x = x + c_i * (p_0 * ... * p_{i-1})

	var result NT
	N(&result).Set(residues[0]) // x = a_0

	var pProd NT
	N(&pProd).SetOne()

	for i := 1; i < params.NumFactors; i++ {
		// Update pProd = p_0 * ... * p_{i-1}
		capMul := algebra.Capacity(N(&pProd).AnnouncedLen() + params.Factors[i-1].Nat().AnnouncedLen())
		N(&pProd).MulCap(N(&pProd), params.Factors[i-1].Nat(), capMul)

		// Compute c_i = (a_i - x) * (p_0 * ... * p_{i-1})^{-1} mod p_i
		var xModPi, diff, ci NT
		params.Factors[i].Mod(N(&xModPi), N(&result))
		params.Factors[i].ModSub(N(&diff), residues[i], N(&xModPi))
		params.Factors[i].ModMul(N(&ci), N(&diff), params.GarnerCoeffs[i][i-1])

		// x = x + c_i * pProd
		var term NT
		capMul = algebra.Capacity(N(&ci).AnnouncedLen() + N(&pProd).AnnouncedLen())
		N(&term).MulCap(N(&ci), N(&pProd), capMul)
		capAdd := algebra.Capacity(N(&result).AnnouncedLen() + N(&term).AnnouncedLen())
		N(&result).AddCap(N(&result), N(&term), capAdd)
	}

	// Clone to return a properly typed value
	return N(&result).Clone(), allOk
}

// DecomposeMultiSerial decomposes m into residues mod each prime.
// Constant-time with respect to values (not the number of primes).
func (params *Params[MM, MF, N, MMT, MFT, NT]) DecomposeSerial(m MM) []N {
	residues := make([]N, params.NumFactors)

	// Process all primes to maintain constant time
	for i := range params.NumFactors {
		var residueT NT
		params.Factors[i].Mod(N(&residueT), m.Nat())
		residues[i] = N(&residueT)
	}

	return residues
}

// DecomposeMultiParallel decomposes m into residues mod each prime in parallel.
// Constant-time with respect to values (not the number of primes).
func (params *Params[MM, MF, N, MMT, MFT, NT]) DecomposeParallel(m MM) []N {
	residues := make([]N, params.NumFactors)
	residueTs := make([]NT, params.NumFactors)

	var wg sync.WaitGroup
	wg.Add(params.NumFactors)

	// Launch all goroutines to maintain constant time
	for i := range params.NumFactors {
		go func(idx int) {
			defer wg.Done()
			params.Factors[idx].Mod(N(&residueTs[idx]), m.Nat())
		}(i)
	}

	wg.Wait()

	// type fix results
	for i := range params.NumFactors {
		residues[i] = N(&residueTs[i])
	}

	return residues
}

// Decompose chooses between serial and parallel based on size.
// The choice is deterministic based on modulus size and prime count.
func (params *Params[MM, MF, N, MMT, MFT, NT]) Decompose(m MM) []N {
	// Use parallel for larger moduli or more primes
	// This is a deterministic choice, not data-dependent
	if m.BitLen() > 4096 || params.NumFactors > 3 {
		return params.DecomposeParallel(m)
	}
	return params.DecomposeSerial(m)
}
