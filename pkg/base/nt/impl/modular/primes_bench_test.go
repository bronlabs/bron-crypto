package modular_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl/modular"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

// BenchmarkOddPrimeFactorsComparison compares OddPrimeFactors vs OddPrimeFactorsMulti
func BenchmarkOddPrimeFactorsComparison(b *testing.B) {
	sizes := []int{1024, 2048}
	
	for _, bits := range sizes {
		b.Run(fmt.Sprintf("%d-bit", bits), func(b *testing.B) {
			// Generate two primes for fair comparison
			p1Big, _ := rand.Prime(rand.Reader, bits)
			p2Big, _ := rand.Prime(rand.Reader, bits)
			
			p1 := (*impl.Nat)(new(saferith.Nat).SetBig(p1Big, bits).Resize(bits))
			p2 := (*impl.Nat)(new(saferith.Nat).SetBig(p2Big, bits).Resize(bits))
			
			// Setup OddPrimeFactors (specialized 2-factor)
			opf, ok1 := modular.NewOddPrimeFactors[*impl.ModulusOdd, *impl.ModulusOddPrime](p1, p2)
			require.Equal(b, ct.True, ok1, "OddPrimeFactors initialization failed")
			
			// Debug: check if p1 and p2 are actually different
			if p1.Equal(p2) == ct.True {
				// Very unlikely but regenerate if they're the same
				p2Big, _ = rand.Prime(rand.Reader, bits)
				p2 = (*impl.Nat)(new(saferith.Nat).SetBig(p2Big, bits).Resize(bits))
			}
			
			// Setup OddPrimeFactorsMulti with THE SAME TWO PRIMES
			opfMulti, ok2 := modular.NewOddPrimeFactorsMulti[*impl.ModulusOdd, *impl.ModulusOddPrime](p1, p2)
			require.Equal(b, ct.True, ok2, "OddPrimeFactorsMulti initialization failed")
			
			// Generate test base and exponent
			nBig := new(saferith.Nat).Mul((*saferith.Nat)(p1), (*saferith.Nat)(p2), -1).Big()
			baseBig, _ := rand.Int(rand.Reader, nBig)
			expBig, _ := rand.Int(rand.Reader, nBig)
			
			base := (*impl.Nat)(new(saferith.Nat).SetBig(baseBig, bits*2))
			exp := (*impl.Nat)(new(saferith.Nat).SetBig(expBig, bits*2))
			
			var result1, result2 impl.Nat
			
			b.Run("OddPrimeFactors", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					opf.Exp(&result1, base, exp)
				}
			})
			
			b.Run("OddPrimeFactorsMulti", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					opfMulti.Exp(&result2, base, exp)
				}
			})
			
			// Verify they produce the same result
			opf.Exp(&result1, base, exp)
			opfMulti.Exp(&result2, base, exp)
			
			// Compare actual values (ignoring capacity/leading zeros)
			bytes1 := result1.Bytes()
			bytes2 := result2.Bytes()
			
			// Skip leading zeros in bytes2 if any
			start := 0
			for start < len(bytes2) && bytes2[start] == 0 {
				start++
			}
			actualBytes2 := bytes2[start:]
			
			require.Equal(b, bytes1, actualBytes2, "Results should be identical")
		})
	}
}

// BenchmarkPaillierSizedExp tests with Paillier-relevant sizes (r^N mod N^2)
func BenchmarkPaillierSizedExp(b *testing.B) {
	sizes := []int{1024, 2048}
	
	for _, bits := range sizes {
		b.Run(fmt.Sprintf("%d-bit-modulus", bits), func(b *testing.B) {
			// Generate two primes of size bits/2 each (so N is bits)
			p1Big, _ := rand.Prime(rand.Reader, bits/2)
			p2Big, _ := rand.Prime(rand.Reader, bits/2)
			
			p1 := (*impl.Nat)(new(saferith.Nat).SetBig(p1Big, bits/2))
			p2 := (*impl.Nat)(new(saferith.Nat).SetBig(p2Big, bits/2))
			
			// Setup both implementations
			opf, _ := modular.NewOddPrimeFactors[*impl.ModulusOdd, *impl.ModulusOddPrime](p1, p2)
			opfMulti, _ := modular.NewOddPrimeFactorsMulti[*impl.ModulusOdd, *impl.ModulusOddPrime](p1, p2)
			
			// N = p * q
			n := new(saferith.Nat).Mul((*saferith.Nat)(p1), (*saferith.Nat)(p2), -1)
			nBig := n.Big()
			
			// Generate random r < N and use N as exponent (Paillier: r^N mod N^2)
			rBig, _ := rand.Int(rand.Reader, nBig)
			r := (*impl.Nat)(new(saferith.Nat).SetBig(rBig, bits))
			expN := (*impl.Nat)(n)
			
			var result impl.Nat
			
			b.Run("OddPrimeFactors", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					opf.Exp(&result, r, expN)
				}
			})
			
			b.Run("OddPrimeFactorsMulti", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					opfMulti.Exp(&result, r, expN)
				}
			})
		})
	}
}