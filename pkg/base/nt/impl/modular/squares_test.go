package modular_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl/modular"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOddPrimeSquareFactorSingle tests the OddPrimeSquareFactorSingle type
func TestOddPrimeSquareFactorSingle(t *testing.T) {
	testCases := []struct {
		name      string
		primeBits int
	}{
		{"32-bit prime", 32},
		{"64-bit prime", 64},
		{"128-bit prime", 128},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a prime
			pBig, _ := rand.Prime(rand.Reader, tc.primeBits)
			p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, tc.primeBits).Resize(tc.primeBits))

			// Create OddPrimeSquareFactorSingle
			// Type parameters: M (Modulus), MO (ModulusOdd), MOP (ModulusOddPrime), N (Nat)
			ops, ok := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)
			require.Equal(t, ct.True, ok, "Creating OddPrimeSquareFactorSingle should succeed")

			// Test exponentiation modulo p^2
			p2 := new(big.Int).Mul(pBig, pBig)
			
			// Generate random base
			baseBig, _ := rand.Int(rand.Reader, p2)
			base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, tc.primeBits*2).Resize(tc.primeBits*2))

			// Generate random exponent
			expBig, _ := rand.Int(rand.Reader, pBig)
			exp := (*impl.Nat)(new(saferith.Nat).SetBig(expBig, tc.primeBits).Resize(tc.primeBits))

			// Compute using OddPrimeSquareFactorSingle
			result := (*impl.Nat)(new(saferith.Nat))
			ok = ops.Exp(result, base, exp)
			assert.Equal(t, ct.True, ok, "Exponentiation should succeed")

			// Verify against standard modular exponentiation
			expectedBig := new(big.Int).Exp(baseBig, expBig, p2)
			resultBig := new(big.Int).SetBytes(result.Bytes())

			assert.Equal(t, 0, expectedBig.Cmp(resultBig), "Result should match standard exponentiation")
			t.Logf("base^exp mod p^2: %v^%v mod %v^2 = %v", baseBig, expBig, pBig, resultBig)
		})
	}
}

// TestOddPrimeSquareFactorsMulti tests the OddPrimeSquareFactorsMulti type
func TestOddPrimeSquareFactorsMulti(t *testing.T) {
	testCases := []struct {
		name       string
		primeBits  int
		numFactors int
	}{
		{"2 factors, 32-bit primes", 32, 2},
		{"3 factors, 32-bit primes", 32, 3},
		{"2 factors, 64-bit primes", 64, 2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate primes
			primes := make([]*big.Int, tc.numFactors)
			primesNat := make([]*impl.Nat, tc.numFactors)
			
			for i := 0; i < tc.numFactors; i++ {
				primes[i], _ = rand.Prime(rand.Reader, tc.primeBits)
				// Ensure primes are different
				for j := 0; j < i; j++ {
					if primes[i].Cmp(primes[j]) == 0 {
						primes[i], _ = rand.Prime(rand.Reader, tc.primeBits)
						j = -1 // Restart check
					}
				}
				primesNat[i] = (*impl.Nat)(new(saferith.Nat).SetBig(primes[i], tc.primeBits).Resize(tc.primeBits))
			}

			// Create OddPrimeSquareFactorsMulti
			// Type parameters: M, MO, MOP, N, MT, MOT, MOPT, NT
			opsm, ok := modular.NewOddPrimeSquareFactorsMulti[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](primesNat...)
			require.Equal(t, ct.True, ok, "Creating OddPrimeSquareFactorsMulti should succeed")

			// Compute N = ∏(p_i^2)
			n := big.NewInt(1)
			for _, p := range primes {
				p2 := new(big.Int).Mul(p, p)
				n.Mul(n, p2)
			}

			// Generate random base
			baseBig, _ := rand.Int(rand.Reader, n)
			base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, tc.primeBits*2*tc.numFactors).Resize(tc.primeBits*2*tc.numFactors))

			// Generate random exponent
			expBig, _ := rand.Int(rand.Reader, primes[0])
			exp := (*impl.Nat)(new(saferith.Nat).SetBig(expBig, tc.primeBits).Resize(tc.primeBits))

			// Compute using OddPrimeSquareFactorsMulti
			result := (*impl.Nat)(new(saferith.Nat))
			ok = opsm.Exp(result, base, exp)
			assert.Equal(t, ct.True, ok, "Multi-factor exponentiation should succeed")

			// Verify against standard modular exponentiation
			expectedBig := new(big.Int).Exp(baseBig, expBig, n)
			resultBig := new(big.Int).SetBytes(result.Bytes())

			assert.Equal(t, 0, expectedBig.Cmp(resultBig), "Result should match standard exponentiation")
			t.Logf("Multi-factor: base^exp mod N = %v", resultBig)
		})
	}
}

// TestTeichmullerDecomposition tests the Teichmüller lifting in OddPrimeSquareFactorSingle
func TestTeichmullerDecomposition(t *testing.T) {
	// Small prime for easy verification
	pBig := big.NewInt(17)
	p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, 64).Resize(64))

	// Create OddPrimeSquareFactorSingle
	ops, ok := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)
	require.Equal(t, ct.True, ok)

	// Test decomposition for various values
	testValues := []int64{1, 5, 10, 15, 100, 288} // 288 = 17^2 - 1

	for _, val := range testValues {
		t.Run(fmt.Sprintf("value_%d", val), func(t *testing.T) {
			valueBig := big.NewInt(val)
			value := (*impl.Nat)(new(saferith.Nat).SetBig(valueBig, 64).Resize(64))

			// Decompose: a = p^m * ω * u where u = 1 + p*t mod p^2
			omega := (*impl.Nat)(new(saferith.Nat))
			tVal := (*impl.Nat)(new(saferith.Nat))
			u := (*impl.Nat)(new(saferith.Nat))
			m := ops.Decompose(omega, tVal, u, value)

			// Verify decomposition
			// Reconstruct: a' = p^m * ω * u mod p^2
			p2 := new(big.Int).Mul(pBig, pBig)
			
			// p^m
			pToM := new(big.Int).Exp(pBig, big.NewInt(int64(m)), p2)
			
			// ω (Teichmüller lift)
			omegaBig := new(big.Int).SetBytes(omega.Bytes())
			
			// u (principal unit)
			uBig := new(big.Int).SetBytes(u.Bytes())
			
			// Reconstruct: p^m * ω * u
			reconstructed := new(big.Int).Mul(pToM, omegaBig)
			reconstructed.Mul(reconstructed, uBig)
			reconstructed.Mod(reconstructed, p2)
			
			// Original value mod p^2
			expected := new(big.Int).Mod(valueBig, p2)
			
			assert.Equal(t, 0, expected.Cmp(reconstructed), 
				"Decomposition should reconstruct original value")
			
			// Verify ω is a Teichmüller lift (ω^p ≡ ω mod p^2)
			omegaToP := new(big.Int).Exp(omegaBig, pBig, p2)
			assert.Equal(t, 0, omegaBig.Cmp(omegaToP), 
				"ω should be a Teichmüller lift (ω^p ≡ ω mod p^2)")
			
			// Verify u is a principal unit (u ≡ 1 mod p)
			uModP := new(big.Int).Mod(uBig, pBig)
			assert.Equal(t, 0, big.NewInt(1).Cmp(uModP), 
				"u should be a principal unit (u ≡ 1 mod p)")
			
			t.Logf("Decomposed %v = %v^%v * %v * %v mod %v^2",
				val, pBig, m, omegaBig, uBig, pBig)
		})
	}
}

// BenchmarkOddPrimeSquare benchmarks OddPrimeSquareFactorSingle vs standard exponentiation
func BenchmarkOddPrimeSquare(b *testing.B) {
	sizes := []int{256, 512, 1024}

	for _, bits := range sizes {
		b.Run(fmt.Sprintf("%d-bit", bits), func(b *testing.B) {
			// Generate prime
			pBig, _ := rand.Prime(rand.Reader, bits)
			p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, bits).Resize(bits))
			p2 := new(big.Int).Mul(pBig, pBig)

			// Create OddPrimeSquareFactorSingle
			ops, _ := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)

			// Generate random base and exponent
			baseBig, _ := rand.Int(rand.Reader, p2)
			base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, bits*2).Resize(bits*2))
			
			expBig, _ := rand.Int(rand.Reader, pBig)
			exp := (*impl.Nat)(new(saferith.Nat).SetBig(expBig, bits).Resize(bits))

			result := (*impl.Nat)(new(saferith.Nat))

			// Benchmark OddPrimeSquareFactorSingle
			b.Run("OddPrimeSquare", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ops.Exp(result, base, exp)
				}
			})

			// Create standard modulus for comparison
			modulus := impl.NewModulusFromNat((*impl.Nat)(new(saferith.Nat).SetBig(p2, bits*2).Resize(bits*2)))

			// Benchmark standard exponentiation
			b.Run("Standard", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					modulus.ModExp(result, base, exp)
				}
			})
		})
	}
}