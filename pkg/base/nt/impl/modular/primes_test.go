package modular_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl/modular"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExpToN tests the ExpToN method for r^N mod N^2 (Paillier case)
func TestExpToN(t *testing.T) {
	testCases := []struct {
		name       string
		primeBits  int
		numFactors int
	}{
		{"2 factors, 32-bit primes", 32, 2},
		{"2 factors, 64-bit primes", 64, 2},
		{"2 factors, 128-bit primes", 128, 2},
		{"3 factors, 32-bit primes", 32, 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate primes
			primes := make([]*big.Int, tc.numFactors)
			primesNat := make([]*impl.Nat, tc.numFactors)

			// Compute N = ∏p_i
			N := big.NewInt(1)

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
				N.Mul(N, primes[i])
			}

			// Compute N^2 = ∏(p_i^2)
			N2 := new(big.Int).Mul(N, N)

			// Convert N to Nat
			NNat := (*impl.Nat)(new(saferith.Nat).SetBig(N, tc.primeBits*tc.numFactors).Resize(tc.primeBits * tc.numFactors))

			// Create OddPrimeSquareFactorsMulti
			opsm, ok := modular.NewOddPrimeSquareFactorsMulti[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](primesNat...)
			require.Equal(t, ct.True, ok, "Creating OddPrimeSquareFactorsMulti should succeed")

			// Test multiple random bases
			for trial := 0; trial < 5; trial++ {
				// Generate random base r with gcd(r, N) = 1
				var r *big.Int
				for {
					r, _ = rand.Int(rand.Reader, N)
					if r.Cmp(big.NewInt(0)) != 0 {
						gcd := new(big.Int).GCD(nil, nil, r, N)
						if gcd.Cmp(big.NewInt(1)) == 0 {
							break
						}
					}
				}

				rNat := (*impl.Nat)(new(saferith.Nat).SetBig(r, tc.primeBits*tc.numFactors).Resize(tc.primeBits * tc.numFactors))

				// Method 1: ExpToN (should compute r^N mod N^2)
				result1 := (*impl.Nat)(new(saferith.Nat))
				ok1 := opsm.ExpToN(result1, rNat)
				assert.Equal(t, ct.True, ok1, "ExpToN should succeed")

				// Method 2: Exp with N as exponent
				result2 := (*impl.Nat)(new(saferith.Nat))
				ok2 := opsm.Exp(result2, rNat, NNat)
				assert.Equal(t, ct.True, ok2, "Exp should succeed")

				// Expected result: r^N mod N^2
				expectedBig := new(big.Int).Exp(r, N, N2)

				// Compare all results
				r1Big := new(big.Int).SetBytes(result1.Bytes())
				r2Big := new(big.Int).SetBytes(result2.Bytes())

				assert.Equal(t, 0, expectedBig.Cmp(r1Big), "ExpToN result should match expected")
				assert.Equal(t, 0, expectedBig.Cmp(r2Big), "Exp result should match expected")
				assert.Equal(t, 0, r1Big.Cmp(r2Big), "ExpToN and Exp should give same result")

				t.Logf("Trial %d: r^N mod N^2 = %v", trial+1, r1Big)
			}
		})
	}
}

// TestExpToN_PaillierCase tests specifically for Paillier encryption scenario
func TestExpToN_PaillierCase(t *testing.T) {
	// Test with Paillier-sized primes
	primeBits := 512 // Will give 1024-bit N

	// Generate two primes p and q
	pBig, _ := rand.Prime(rand.Reader, primeBits)
	qBig, _ := rand.Prime(rand.Reader, primeBits)

	// Ensure different
	for pBig.Cmp(qBig) == 0 {
		qBig, _ = rand.Prime(rand.Reader, primeBits)
	}

	p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, primeBits).Resize(primeBits))
	q := (*impl.Nat)(new(saferith.Nat).SetBig(qBig, primeBits).Resize(primeBits))

	// N = p * q
	N := new(big.Int).Mul(pBig, qBig)
	N2 := new(big.Int).Mul(N, N)
	NNat := (*impl.Nat)(new(saferith.Nat).SetBig(N, primeBits*2).Resize(primeBits * 2))

	// Create OddPrimeSquareFactorsMulti
	opsm, ok := modular.NewOddPrimeSquareFactorsMulti[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p, q)
	require.Equal(t, ct.True, ok)

	// In Paillier, we compute r^N mod N^2 for random r
	// This is used in encryption: c = g^m * r^N mod N^2

	// Generate random r with gcd(r, N) = 1
	var r *big.Int
	for {
		r, _ = rand.Int(rand.Reader, N)
		if r.Cmp(big.NewInt(0)) != 0 {
			gcd := new(big.Int).GCD(nil, nil, r, N)
			if gcd.Cmp(big.NewInt(1)) == 0 {
				break
			}
		}
	}

	rNat := (*impl.Nat)(new(saferith.Nat).SetBig(r, primeBits*2).Resize(primeBits * 2))

	// Test ExpToN
	resultExpToN := (*impl.Nat)(new(saferith.Nat))
	okExpToN := opsm.ExpToN(resultExpToN, rNat)
	assert.Equal(t, ct.True, okExpToN, "ExpToN should succeed")

	// Test regular Exp
	resultExp := (*impl.Nat)(new(saferith.Nat))
	okExp := opsm.Exp(resultExp, rNat, NNat)
	assert.Equal(t, ct.True, okExp, "Exp should succeed")

	// Expected
	expected := new(big.Int).Exp(r, N, N2)

	// Convert results
	expToNBig := new(big.Int).SetBytes(resultExpToN.Bytes())
	expBig := new(big.Int).SetBytes(resultExp.Bytes())

	// Verify
	assert.Equal(t, 0, expected.Cmp(expToNBig), "ExpToN should match expected")
	assert.Equal(t, 0, expected.Cmp(expBig), "Exp should match expected")

	t.Logf("Paillier r^N mod N^2: %v", expToNBig)

	// Also verify this is a valid Paillier encryption of 0
	// E(0, r) = (1+N)^0 * r^N mod N^2 = r^N mod N^2
	// Decryption should give 0
}

// BenchmarkExpToN benchmarks ExpToN vs Exp for r^N mod N^2
func BenchmarkExpToN(b *testing.B) {
	testCases := []struct {
		name      string
		primeBits int
		numPrimes int
	}{
		{"256-bit primes (512-bit N)", 256, 2},
		{"512-bit primes (1024-bit N)", 512, 2},
		{"1024-bit primes (2048-bit N)", 1024, 2},
		{"1536-bit primes (3072-bit N)", 1536, 2},
		{"2048-bit primes (4096-bit N)", 2048, 2},
		{"512-bit primes, 3 factors", 512, 3},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Generate primes
			primes := make([]*big.Int, tc.numPrimes)
			primesNat := make([]*impl.Nat, tc.numPrimes)
			N := big.NewInt(1)

			for i := 0; i < tc.numPrimes; i++ {
				primes[i], _ = rand.Prime(rand.Reader, tc.primeBits)
				// Ensure different
				for j := 0; j < i; j++ {
					if primes[i].Cmp(primes[j]) == 0 {
						primes[i], _ = rand.Prime(rand.Reader, tc.primeBits)
						j = -1
					}
				}
				primesNat[i] = (*impl.Nat)(new(saferith.Nat).SetBig(primes[i], tc.primeBits).Resize(tc.primeBits))
				N.Mul(N, primes[i])
			}

			NNat := (*impl.Nat)(new(saferith.Nat).SetBig(N, tc.primeBits*tc.numPrimes).Resize(tc.primeBits * tc.numPrimes))

			// Create OddPrimeSquareFactorsMulti
			opsm, ok := modular.NewOddPrimeSquareFactorsMulti[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](primesNat...)
			require.Equal(b, ct.True, ok)

			// Also create OddPrimeFactorsMulti for comparison
			opfm, ok := modular.NewOddPrimeFactorsMulti[*impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](primesNat...)
			require.Equal(b, ct.True, ok)

			// Generate random base
			var r *big.Int
			for {
				r, _ = rand.Int(rand.Reader, N)
				if r.Cmp(big.NewInt(0)) != 0 {
					gcd := new(big.Int).GCD(nil, nil, r, N)
					if gcd.Cmp(big.NewInt(1)) == 0 {
						break
					}
				}
			}

			rNat := (*impl.Nat)(new(saferith.Nat).SetBig(r, tc.primeBits*tc.numPrimes).Resize(tc.primeBits * tc.numPrimes))
			result := (*impl.Nat)(new(saferith.Nat))

			// Benchmark ExpToN (specialized for r^N)
			b.Run("ExpToN", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ok := opsm.ExpToN(result, rNat)
					if ok != ct.True {
						b.Fatal("ExpToN failed")
					}
				}
			})

			// Benchmark Exp with N as exponent
			b.Run("Exp(r,N)", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ok := opsm.Exp(result, rNat, NNat)
					if ok != ct.True {
						b.Fatal("Exp failed")
					}
				}
			})

			// Benchmark OddPrimeFactorsMulti.Exp for comparison (mod N, not N^2)
			// This would need to be squared to get the same result
			b.Run("OddPrimeFactors.Exp(r,N)", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ok := opfm.Exp(result, rNat, NNat)
					if ok != ct.True {
						b.Fatal("OddPrimeFactors.Exp failed")
					}
				}
			})
		})
	}
}

// TestDecomposeExactDivision tests that Decompose correctly performs exact division
// when computing t from the principal unit q = 1 + p*t
func TestDecomposeExactDivision(t *testing.T) {
	// Use a small prime for easier debugging
	pBig := big.NewInt(7)
	p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, 64).Resize(64))

	ops, ok := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)
	require.Equal(t, ct.True, ok)

	// Test case 1: a = 15 mod 49
	// 15 = 3 * 5 (both coprime to 7)
	// We expect: m = 0 (unit), w = Teichmüller lift, and specific t value
	a := (*impl.Nat)(new(saferith.Nat).SetUint64(15))

	var w, tResult, u impl.Nat
	m := ops.Decompose(&w, &tResult, &u, a)

	assert.Equal(t, 0, m, "15 should be a unit (m=0)")

	// Verify the decomposition: a ≡ p^m * w * (1 + p*t) mod p^2
	// Since m=0: a ≡ w * (1 + p*t) mod p^2
	p2Big := new(big.Int).Mul(pBig, pBig) // 49

	// Calculate w * (1 + p*t) mod p^2
	wBig := new(big.Int).SetBytes(w.Bytes())
	tBig := new(big.Int).SetBytes(tResult.Bytes())

	// 1 + p*t
	principalUnit := new(big.Int).Mul(pBig, tBig)
	principalUnit.Add(principalUnit, big.NewInt(1))

	// w * (1 + p*t)
	result := new(big.Int).Mul(wBig, principalUnit)
	result.Mod(result, p2Big)

	// Should equal a mod p^2
	aMod := new(big.Int).Mod(big.NewInt(15), p2Big)
	assert.Equal(t, aMod, result, "Decomposition should reconstruct a")

	// Verify u = 1 + p*t
	uBig := new(big.Int).SetBytes(u.Bytes())
	assert.Equal(t, principalUnit.Uint64(), uBig.Uint64(), "u should equal 1 + p*t")

	// Test case 2: a = 8 mod 49
	// 8 = 1 + 7*1, so this is already a principal unit
	a2 := (*impl.Nat)(new(saferith.Nat).SetUint64(8))

	var w2, t2, u2 impl.Nat
	m2 := ops.Decompose(&w2, &t2, &u2, a2)

	assert.Equal(t, 0, m2, "8 should be a unit (m=0)")

	// For a principal unit, w should be 1 and t should satisfy a = 1 + p*t
	w2Big := new(big.Int).SetBytes(w2.Bytes())
	t2Big := new(big.Int).SetBytes(t2.Bytes())

	// Verify: 8 = w2 * (1 + 7*t2) mod 49
	principalUnit2 := new(big.Int).Mul(pBig, t2Big)
	principalUnit2.Add(principalUnit2, big.NewInt(1))

	result2 := new(big.Int).Mul(w2Big, principalUnit2)
	result2.Mod(result2, p2Big)

	assert.Equal(t, uint64(8), result2.Uint64(), "Should reconstruct 8")

	// The key test: t should be exactly (u - 1) / p
	// If ModDiv is used incorrectly, this division might not be exact
	u2Big := new(big.Int).SetBytes(u2.Bytes())
	u2Minus1 := new(big.Int).Sub(u2Big, big.NewInt(1))

	// This should divide exactly
	tExpected := new(big.Int).Div(u2Minus1, pBig)
	remainder := new(big.Int).Mod(u2Minus1, pBig)

	assert.Equal(t, int64(0), remainder.Int64(), "(u-1) should be divisible by p")
	assert.Equal(t, tExpected.Uint64(), t2Big.Uint64(), "t should be exactly (u-1)/p")

	// Test case 3: a = 7 (has valuation 1)
	a3 := (*impl.Nat)(new(saferith.Nat).SetUint64(7))

	var w3, t3, u3 impl.Nat
	m3 := ops.Decompose(&w3, &t3, &u3, a3)

	assert.Equal(t, 1, m3, "7 should have valuation 1")

	// For m=1: a ≡ p * w * (1 + p*t) mod p^2
	w3Big := new(big.Int).SetBytes(w3.Bytes())
	t3Big := new(big.Int).SetBytes(t3.Bytes())

	principalUnit3 := new(big.Int).Mul(pBig, t3Big)
	principalUnit3.Add(principalUnit3, big.NewInt(1))

	// p * w * (1 + p*t)
	result3 := new(big.Int).Mul(pBig, w3Big)
	result3.Mul(result3, principalUnit3)
	result3.Mod(result3, p2Big)

	assert.Equal(t, uint64(7), result3.Uint64(), "Should reconstruct 7")
}

// TestDecomposeModDivBug specifically tests that the division (q-1)/p is done correctly
// This test will fail if ModDiv is used instead of exact integer division
func TestDecomposeModDivBug(t *testing.T) {
	// Use p = 11 for variety
	pBig := big.NewInt(11)
	p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, 64).Resize(64))

	ops, ok := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)
	require.Equal(t, ct.True, ok)

	p2Big := new(big.Int).Mul(pBig, pBig) // 121

	// Construct a number that is specifically 1 + 11*t for some t
	// Let's use t = 3, so a = 1 + 11*3 = 34
	targetT := int64(3)
	a := (*impl.Nat)(new(saferith.Nat).SetUint64(uint64(1 + 11*targetT)))

	var w, tResult, u impl.Nat
	m := ops.Decompose(&w, &tResult, &u, a)

	assert.Equal(t, 0, m, "34 should be a unit")

	// w should be the Teichmüller lift of 34 mod 11 = 1
	// So w^11 ≡ 1 mod 121, which means w = 1
	wBig := new(big.Int).SetBytes(w.Bytes())
	assert.Equal(t, int64(1), wBig.Int64(), "Teichmüller lift of 1 should be 1")

	// The crucial test: t should be exactly 3
	tBig := new(big.Int).SetBytes(tResult.Bytes())
	assert.Equal(t, targetT, tBig.Int64(), "t should be exactly 3")

	// Verify u = 1 + 11*3 = 34
	uBig := new(big.Int).SetBytes(u.Bytes())
	assert.Equal(t, int64(34), uBig.Int64(), "u should be 34")

	// Double-check the reconstruction
	principalUnit := new(big.Int).Mul(pBig, tBig)
	principalUnit.Add(principalUnit, big.NewInt(1))

	result := new(big.Int).Mul(wBig, principalUnit)
	result.Mod(result, p2Big)

	assert.Equal(t, int64(34), result.Int64(), "Should reconstruct 34")
}

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
			p2 := (*impl.Nat)(new(saferith.Nat).SetBig(p2Big, tc.primeBits*2).Resize(tc.primeBits * 2))

			// Generate random base and exponent
			baseBig, _ := rand.Int(rand.Reader, p2Big)
			base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, tc.primeBits*2).Resize(tc.primeBits * 2))

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
			p2 := (*impl.Nat)(new(saferith.Nat).SetBig(p2Big, tc.primeBits*2).Resize(tc.primeBits * 2))

			// Compute λ(n) = lcm(p-1, q-1) - Paillier decryption exponent
			pMinus1 := new(big.Int).Sub(pBig, big.NewInt(1))
			qMinus1 := new(big.Int).Sub(qBig, big.NewInt(1))
			gcd := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
			lambda := new(big.Int).Mul(pMinus1, qMinus1)
			lambda.Div(lambda, gcd)

			lambdaNat := (*impl.Nat)(new(saferith.Nat).SetBig(lambda, tc.primeBits*2).Resize(tc.primeBits * 2))

			// Generate random base (Paillier ciphertext-like)
			baseBig, _ := rand.Int(rand.Reader, p2Big)
			base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, tc.primeBits*2).Resize(tc.primeBits * 2))

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
				values[i] = (*impl.Nat)(new(saferith.Nat).SetBig(valBig, tc.primeBits*2).Resize(tc.primeBits * 2))
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
