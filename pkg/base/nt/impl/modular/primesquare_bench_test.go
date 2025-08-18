package modular_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl/modular"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

// BenchmarkPrimeSquareExp benchmarks a^b mod p^2 using OddPrimeSquareFactorSingle
// vs creating p^2 as ModulusOdd and using standard exponentiation
func BenchmarkPrimeSquareExp(b *testing.B) {
	testCases := []struct {
		name      string
		primeBits int
		expBits   int
	}{
		{"512-bit prime, 256-bit exp", 512, 256},
		{"512-bit prime, 512-bit exp", 512, 512},
		{"1024-bit prime, 512-bit exp", 1024, 512},
		{"1024-bit prime, 1024-bit exp", 1024, 1024},
		{"2048-bit prime, 1024-bit exp", 2048, 1024},
		{"2048-bit prime, 2048-bit exp", 2048, 2048},
		{"3072-bit prime, 1536-bit exp", 3072, 1536},
		{"3072-bit prime, 3072-bit exp", 3072, 3072},
		{"4096-bit prime, 2048-bit exp", 4096, 2048},
		{"4096-bit prime, 4096-bit exp", 4096, 4096},
		{"5120-bit prime, 2560-bit exp", 5120, 2560},
		{"5120-bit prime, 5120-bit exp", 5120, 5120},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Generate a prime
			pBig, _ := rand.Prime(rand.Reader, tc.primeBits)
			p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, tc.primeBits).Resize(tc.primeBits))

			// Create p^2
			p2Big := new(big.Int).Mul(pBig, pBig)
			p2 := (*impl.Nat)(new(saferith.Nat).SetBig(p2Big, tc.primeBits*2).Resize(tc.primeBits*2))

			// Generate random base and exponent
			baseBig, _ := rand.Int(rand.Reader, p2Big)
			base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, tc.primeBits*2).Resize(tc.primeBits*2))

			expBig, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(tc.expBits)))
			exp := (*impl.Nat)(new(saferith.Nat).SetBig(expBig, tc.expBits).Resize(tc.expBits))

			// Create OddPrimeSquareFactorSingle
			ops, ok := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)
			require.Equal(b, ct.True, ok, "Creating OddPrimeSquareFactorSingle should succeed")

			// Create standard ModulusOdd for p^2
			var modP2 impl.ModulusOdd
			ok = modP2.SetNat(p2)
			require.Equal(b, ct.True, ok, "Creating ModulusOdd should succeed")

			// Result holders
			result1 := (*impl.Nat)(new(saferith.Nat))
			result2 := (*impl.Nat)(new(saferith.Nat))

			// Benchmark OddPrimeSquareFactorSingle.Exp
			b.Run("OddPrimeSquare", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ops.Exp(result1, base, exp)
				}
			})

			// Benchmark standard ModulusOdd.Exp
			b.Run("StandardModulus", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					modP2.ModExp(result2, base, exp)
				}
			})

			// Verify both give same result (just once, not in benchmark)
			ops.Exp(result1, base, exp)
			modP2.ModExp(result2, base, exp)
			
			r1Big := new(big.Int).SetBytes(result1.Bytes())
			r2Big := new(big.Int).SetBytes(result2.Bytes())
			
			if r1Big.Cmp(r2Big) != 0 {
				b.Errorf("Results don't match: OddPrimeSquare=%v, Standard=%v", r1Big, r2Big)
			}
		})
	}
}

// BenchmarkPrimeSquareExpSpecial benchmarks with special exponents relevant to Paillier
func BenchmarkPrimeSquareExpSpecial(b *testing.B) {
	testCases := []struct {
		name      string
		primeBits int
	}{
		{"1024-bit prime", 1024},
		{"2048-bit prime", 2048},
		{"3072-bit prime", 3072},
		{"4096-bit prime", 4096},
		{"5120-bit prime", 5120},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Generate two primes for Paillier-like setup
			pBig, _ := rand.Prime(rand.Reader, tc.primeBits)
			qBig, _ := rand.Prime(rand.Reader, tc.primeBits)
			
			// Ensure different
			for pBig.Cmp(qBig) == 0 {
				qBig, _ = rand.Prime(rand.Reader, tc.primeBits)
			}

			p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, tc.primeBits).Resize(tc.primeBits))

			// Create p^2
			p2Big := new(big.Int).Mul(pBig, pBig)
			p2 := (*impl.Nat)(new(saferith.Nat).SetBig(p2Big, tc.primeBits*2).Resize(tc.primeBits*2))

			// Compute λ(n) = lcm(p-1, q-1) - Paillier decryption exponent
			pMinus1 := new(big.Int).Sub(pBig, big.NewInt(1))
			qMinus1 := new(big.Int).Sub(qBig, big.NewInt(1))
			gcd := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
			lambda := new(big.Int).Mul(pMinus1, qMinus1)
			lambda.Div(lambda, gcd)
			
			lambdaNat := (*impl.Nat)(new(saferith.Nat).SetBig(lambda, tc.primeBits*2).Resize(tc.primeBits*2))

			// Generate random base (Paillier ciphertext-like)
			baseBig, _ := rand.Int(rand.Reader, p2Big)
			base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, tc.primeBits*2).Resize(tc.primeBits*2))

			// Create OddPrimeSquareFactorSingle
			ops, ok := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)
			require.Equal(b, ct.True, ok)

			// Create standard ModulusOdd for p^2
			var modP2 impl.ModulusOdd
			ok = modP2.SetNat(p2)
			require.Equal(b, ct.True, ok)

			result1 := (*impl.Nat)(new(saferith.Nat))
			result2 := (*impl.Nat)(new(saferith.Nat))

			// Benchmark with λ(n) as exponent (Paillier decryption case)
			b.Run("λ(n)/OddPrimeSquare", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ops.Exp(result1, base, lambdaNat)
				}
			})

			b.Run("λ(n)/StandardModulus", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					modP2.ModExp(result2, base, lambdaNat)
				}
			})

			// Test with small exponents
			smallExp := (*impl.Nat)(new(saferith.Nat).SetBig(big.NewInt(3), 64).Resize(64))

			b.Run("SmallExp/OddPrimeSquare", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ops.Exp(result1, base, smallExp)
				}
			})

			b.Run("SmallExp/StandardModulus", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					modP2.ModExp(result2, base, smallExp)
				}
			})
		})
	}
}

// BenchmarkPrimeSquareDecompose benchmarks just the decomposition step
func BenchmarkPrimeSquareDecompose(b *testing.B) {
	testCases := []struct {
		name      string
		primeBits int
	}{
		{"512-bit prime", 512},
		{"1024-bit prime", 1024},
		{"2048-bit prime", 2048},
		{"3072-bit prime", 3072},
		{"4096-bit prime", 4096},
		{"5120-bit prime", 5120},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Generate a prime
			pBig, _ := rand.Prime(rand.Reader, tc.primeBits)
			p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, tc.primeBits).Resize(tc.primeBits))

			// Create OddPrimeSquareFactorSingle
			ops, ok := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)
			require.Equal(b, ct.True, ok)

			// Generate random values to decompose
			p2Big := new(big.Int).Mul(pBig, pBig)
			values := make([]*impl.Nat, 100)
			for i := range values {
				valBig, _ := rand.Int(rand.Reader, p2Big)
				values[i] = (*impl.Nat)(new(saferith.Nat).SetBig(valBig, tc.primeBits*2).Resize(tc.primeBits*2))
			}

			omega := (*impl.Nat)(new(saferith.Nat))
			tVal := (*impl.Nat)(new(saferith.Nat))
			u := (*impl.Nat)(new(saferith.Nat))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ops.Decompose(omega, tVal, u, values[i%100])
			}
		})
	}
}