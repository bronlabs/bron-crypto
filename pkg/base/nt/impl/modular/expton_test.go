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
			NNat := (*impl.Nat)(new(saferith.Nat).SetBig(N, tc.primeBits*tc.numFactors).Resize(tc.primeBits*tc.numFactors))

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
				
				rNat := (*impl.Nat)(new(saferith.Nat).SetBig(r, tc.primeBits*tc.numFactors).Resize(tc.primeBits*tc.numFactors))

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
	NNat := (*impl.Nat)(new(saferith.Nat).SetBig(N, primeBits*2).Resize(primeBits*2))
	
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
	
	rNat := (*impl.Nat)(new(saferith.Nat).SetBig(r, primeBits*2).Resize(primeBits*2))
	
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
			
			NNat := (*impl.Nat)(new(saferith.Nat).SetBig(N, tc.primeBits*tc.numPrimes).Resize(tc.primeBits*tc.numPrimes))

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
			
			rNat := (*impl.Nat)(new(saferith.Nat).SetBig(r, tc.primeBits*tc.numPrimes).Resize(tc.primeBits*tc.numPrimes))
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