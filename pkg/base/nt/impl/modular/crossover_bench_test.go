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
	"github.com/stretchr/testify/require"
)

// BenchmarkCrossoverPoint tries to find where OddPrimeSquare becomes competitive
func BenchmarkCrossoverPoint(b *testing.B) {
	// Test with various prime sizes to find crossover point
	primeSizes := []int{
		256, 384, 512, 768, 1024, 1536, 2048, 2560, 3072, 3584, 4096, 4608, 5120, 6144, 7168, 8192,
	}

	// Test with different exponent sizes relative to prime
	expRatios := []struct {
		name  string
		ratio float64 // exponent size as fraction of prime size
	}{
		{"exp=prime/4", 0.25},
		{"exp=prime/2", 0.5},
		{"exp=prime", 1.0},
		{"exp=2*prime", 2.0}, // Like λ(n) in Paillier
	}

	results := make(map[string][]string)

	for _, ratio := range expRatios {
		b.Run(ratio.name, func(b *testing.B) {
			for _, primeBits := range primeSizes {
				expBits := int(float64(primeBits) * ratio.ratio)
				
				b.Run(fmt.Sprintf("%d-bit-prime", primeBits), func(b *testing.B) {
					// Generate prime
					pBig, _ := rand.Prime(rand.Reader, primeBits)
					p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, primeBits).Resize(primeBits))

					// Create p^2
					p2Big := new(big.Int).Mul(pBig, pBig)
					p2 := (*impl.Nat)(new(saferith.Nat).SetBig(p2Big, primeBits*2).Resize(primeBits*2))

					// Generate base and exponent
					baseBig, _ := rand.Int(rand.Reader, p2Big)
					base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, primeBits*2).Resize(primeBits*2))

					expBig, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(expBits)))
					exp := (*impl.Nat)(new(saferith.Nat).SetBig(expBig, expBits).Resize(expBits))

					// Create OddPrimeSquareFactorSingle
					ops, ok := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)
					require.Equal(b, ct.True, ok)

					// Create standard ModulusOdd
					var modP2 impl.ModulusOdd
					ok = modP2.SetNat(p2)
					require.Equal(b, ct.True, ok)

					result := (*impl.Nat)(new(saferith.Nat))

					// Measure OddPrimeSquare
					b.Run("OPS", func(b *testing.B) {
						for i := 0; i < b.N; i++ {
							ops.Exp(result, base, exp)
						}
					})

					// Measure Standard
					b.Run("Std", func(b *testing.B) {
						for i := 0; i < b.N; i++ {
							modP2.ModExp(result, base, exp)
						}
					})
				})
			}
		})
	}

	// Print summary comparison
	for name, res := range results {
		fmt.Printf("\n%s:\n%s\n", name, res)
	}
}

// BenchmarkSpecificCases tests specific cryptographic scenarios
func BenchmarkSpecificCases(b *testing.B) {
	testCases := []struct {
		name        string
		primeBits   int
		setupExp    func(pBig, qBig *big.Int) *big.Int
		description string
	}{
		{
			"Paillier-λ(n)",
			1024,
			func(pBig, qBig *big.Int) *big.Int {
				// λ(n) = lcm(p-1, q-1)
				pMinus1 := new(big.Int).Sub(pBig, big.NewInt(1))
				qMinus1 := new(big.Int).Sub(qBig, big.NewInt(1))
				gcd := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
				lambda := new(big.Int).Mul(pMinus1, qMinus1)
				return lambda.Div(lambda, gcd)
			},
			"Paillier decryption exponent",
		},
		{
			"RSA-d-mod-p-1",
			1024,
			func(pBig, qBig *big.Int) *big.Int {
				// Simulate RSA private exponent mod (p-1)
				// d is typically close to φ(n) in size
				pMinus1 := new(big.Int).Sub(pBig, big.NewInt(1))
				d, _ := rand.Int(rand.Reader, pMinus1)
				return d
			},
			"RSA CRT exponent",
		},
		{
			"Small-Fermat",
			1024,
			func(pBig, qBig *big.Int) *big.Int {
				// a^(p-1) mod p^2 - testing Fermat's little theorem extension
				return new(big.Int).Sub(pBig, big.NewInt(1))
			},
			"Fermat exponent p-1",
		},
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("%s-%d-bit", tc.name, tc.primeBits), func(b *testing.B) {
			// Generate two primes
			pBig, _ := rand.Prime(rand.Reader, tc.primeBits)
			qBig, _ := rand.Prime(rand.Reader, tc.primeBits)
			for pBig.Cmp(qBig) == 0 {
				qBig, _ = rand.Prime(rand.Reader, tc.primeBits)
			}

			p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, tc.primeBits).Resize(tc.primeBits))
			
			// Create p^2
			p2Big := new(big.Int).Mul(pBig, pBig)
			p2 := (*impl.Nat)(new(saferith.Nat).SetBig(p2Big, tc.primeBits*2).Resize(tc.primeBits*2))

			// Generate exponent using test case function
			expBig := tc.setupExp(pBig, qBig)
			expBits := expBig.BitLen()
			exp := (*impl.Nat)(new(saferith.Nat).SetBig(expBig, expBits).Resize(expBits))

			// Generate random base
			baseBig, _ := rand.Int(rand.Reader, p2Big)
			base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, tc.primeBits*2).Resize(tc.primeBits*2))

			// Create implementations
			ops, _ := modular.NewOddPrimeSquareFactorSingle[*impl.Modulus, *impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](p)
			var modP2 impl.ModulusOdd
			modP2.SetNat(p2)

			result := (*impl.Nat)(new(saferith.Nat))

			b.Run("OddPrimeSquare", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					ops.Exp(result, base, exp)
				}
			})

			b.Run("Standard", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					modP2.ModExp(result, base, exp)
				}
			})
		})
	}
}