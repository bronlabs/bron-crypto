package crt_test

import (
	"crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl/crt"
	"github.com/cronokirby/saferith"
)

// Helper to create a ModulusOddPrime from uint64
func benchModulusFromUint64(v uint64) *impl.ModulusOddPrime {
	n := new(saferith.Nat).SetUint64(v)
	return (*impl.ModulusOddPrime)(saferith.ModulusFromNat(n))
}

// Helper to create a Nat from uint64
func benchNatFromUint64(v uint64) *impl.Nat {
	return (*impl.Nat)(new(saferith.Nat).SetUint64(v))
}

// Benchmark Decompose (parallel version) with PrecomputeExtended
func BenchmarkDecompose(b *testing.B) {
	sizes := []struct {
		name string
		pVal uint64
		qVal uint64
	}{
		{"Small_7x11", 7, 11},
		{"Medium_97x101", 97, 101},
		{"Large_1009x1013", 1009, 1013},
		{"VeryLarge_10007x10009", 10007, 10009},
		{"Huge_100003x100019", 100003, 100019},
	}

	for _, tc := range sizes {
		b.Run(tc.name, func(b *testing.B) {
			// Create p as modulus and q as nat
			pMod := benchModulusFromUint64(tc.pVal)
			qNat := benchNatFromUint64(tc.qVal)

			// Compute m = p*q as the modulus
			pNat := benchNatFromUint64(tc.pVal)
			mNat := new(saferith.Nat).Mul((*saferith.Nat)(pNat), (*saferith.Nat)(qNat), 256)
			m := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(mNat))

			// Precompute extended CRT parameters
			prmx, _ := crt.PrecomputeExtended(pMod, qNat)

			b.ResetTimer()
			for b.Loop() {
				mp, mq := prmx.DecomposeParallel(m)
				// Prevent compiler optimization
				_ = mp
				_ = mq
			}
		})
	}
}

// Benchmark DecomposeSerial with PrecomputeExtended
func BenchmarkDecomposeSerial(b *testing.B) {
	sizes := []struct {
		name string
		pVal uint64
		qVal uint64
	}{
		{"Small_7x11", 7, 11},
		{"Medium_97x101", 97, 101},
		{"Large_1009x1013", 1009, 1013},
		{"VeryLarge_10007x10009", 10007, 10009},
		{"Huge_100003x100019", 100003, 100019},
	}

	for _, tc := range sizes {
		b.Run(tc.name, func(b *testing.B) {
			// Create p as modulus and q as nat
			pMod := benchModulusFromUint64(tc.pVal)
			qNat := benchNatFromUint64(tc.qVal)

			// Compute m = p*q as the modulus
			pNat := benchNatFromUint64(tc.pVal)
			mNat := new(saferith.Nat).Mul((*saferith.Nat)(pNat), (*saferith.Nat)(qNat), 256)
			m := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(mNat))

			// Precompute extended CRT parameters
			prmx, _ := crt.PrecomputeExtended(pMod, qNat)

			b.ResetTimer()
			for b.Loop() {
				mp, mq := prmx.DecomposeSerial(m)
				// Prevent compiler optimization
				_ = mp
				_ = mq
			}
		})
	}
}

// Direct comparison benchmark
func BenchmarkDecomposeComparison(b *testing.B) {
	// Use a medium-sized example for direct comparison
	pMod := benchModulusFromUint64(1009)
	qNat := benchNatFromUint64(1013)

	// Compute m = p*q as the modulus
	pNat := benchNatFromUint64(1009)
	mNat := new(saferith.Nat).Mul((*saferith.Nat)(pNat), (*saferith.Nat)(qNat), 256)
	m := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(mNat))

	// Precompute extended CRT parameters
	prmx, _ := crt.PrecomputeExtended(pMod, qNat)

	b.Run("Parallel", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeParallel(m)
			_ = mp
			_ = mq
		}
	})

	b.Run("Serial", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeSerial(m)
			_ = mp
			_ = mq
		}
	})
}

// Benchmark with very large moduli (256-bit primes)
func BenchmarkDecomposeLargeBitSize(b *testing.B) {
	// Use actual 256-bit primes
	// These are actual primes near 2^256
	p256Nat := new(saferith.Nat)
	p256Nat.SetHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")

	q256Nat := new(saferith.Nat)
	q256Nat.SetHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc47")

	pMod := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(p256Nat))
	qNat := (*impl.Nat)(q256Nat)

	// Compute m = p*q as the modulus (will be ~512 bits)
	mNat := new(saferith.Nat).Mul(p256Nat, q256Nat, 512)
	m := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(mNat))

	// Precompute extended CRT parameters
	prmx, _ := crt.PrecomputeExtended(pMod, qNat)

	b.Run("Parallel_256bit", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeParallel(m)
			_ = mp
			_ = mq
		}
	})

	b.Run("Serial_256bit", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeSerial(m)
			_ = mp
			_ = mq
		}
	})
}

// Benchmark parallel vs serial for different GOMAXPROCS values
func BenchmarkDecomposeWithGOMAXPROCS(b *testing.B) {
	// This benchmark can be run with different GOMAXPROCS values to see the effect
	// Run with: GOMAXPROCS=1 go test -bench=BenchmarkDecomposeWithGOMAXPROCS
	// Run with: GOMAXPROCS=2 go test -bench=BenchmarkDecomposeWithGOMAXPROCS
	// Run with: GOMAXPROCS=4 go test -bench=BenchmarkDecomposeWithGOMAXPROCS
	// etc.

	pMod := benchModulusFromUint64(10007)
	qNat := benchNatFromUint64(10009)

	// Compute m = p*q as the modulus
	pNat := benchNatFromUint64(10007)
	mNat := new(saferith.Nat).Mul((*saferith.Nat)(pNat), (*saferith.Nat)(qNat), 256)
	m := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(mNat))

	// Precompute extended CRT parameters
	prmx, _ := crt.PrecomputeExtended(pMod, qNat)

	b.Run("Parallel", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeParallel(m)
			_ = mp
			_ = mq
		}
	})

	b.Run("Serial", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeSerial(m)
			_ = mp
			_ = mq
		}
	})
}

// Generate a random prime of specified bit size
func generatePrime(bits int) *saferith.Nat {
	prime, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return new(saferith.Nat).SetBig(prime, bits)
}

// Benchmark with Paillier-sized parameters
func BenchmarkDecomposePaillier2048(b *testing.B) {
	// Generate 2048-bit primes p and q (like in Paillier)
	p2048 := generatePrime(2048)
	q2048 := generatePrime(2048)
	q := (*impl.Nat)(q2048)

	// Generate a 4096-bit value m (since n = p*q is ~4096 bits)
	mNat := new(saferith.Nat).Mul(p2048, q2048, 4096)
	mModulus := saferith.ModulusFromNat(mNat)
	m := (*impl.ModulusOddPrime)(mModulus)

	pModulus := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(p2048))

	prmx, _ := crt.PrecomputeExtended(pModulus, q)

	b.Run("Parallel_2048bit", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeParallel(m)
			_ = mp
			_ = mq
		}
	})

	b.Run("Serial_2048bit", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeSerial(m)
			_ = mp
			_ = mq
		}
	})
}

// Benchmark with different Paillier key sizes
func BenchmarkDecomposePaillierSizes(b *testing.B) {
	sizes := []struct {
		name      string
		primeBits int
	}{
		{"1024bit_primes", 1024}, // 2048-bit modulus
		{"2048bit_primes", 2048}, // 4096-bit modulus
		{"3072bit_primes", 3072}, // 6144-bit modulus
		{"4096bit_primes", 4096}, // 8192-bit modulus
	}

	for _, size := range sizes {
		// Generate primes once for this size
		p := generatePrime(size.primeBits)
		q := generatePrime(size.primeBits)

		// Compute modulus m = p*q
		mNat := new(saferith.Nat).Mul(p, q, size.primeBits*2)
		m := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(mNat))

		pMod := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(p))
		qNat := (*impl.Nat)(q)

		// Precompute extended CRT parameters
		prmx, _ := crt.PrecomputeExtended(pMod, qNat)

		b.Run(size.name+"_Parallel", func(b *testing.B) {
			for b.Loop() {
				mp, mq := prmx.DecomposeParallel(m)
				_ = mp
				_ = mq
			}
		})

		b.Run(size.name+"_Serial", func(b *testing.B) {
			for b.Loop() {
				mp, mq := prmx.DecomposeSerial(m)
				_ = mp
				_ = mq
			}
		})
	}
}

// Benchmark the complete CRT operation for Paillier
func BenchmarkCRTCompletePaillier(b *testing.B) {
	// Generate 2048-bit primes
	p2048 := generatePrime(2048)
	q2048 := generatePrime(2048)

	pMod := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(p2048))
	qNat := (*impl.Nat)(q2048)

	// Precompute CRT parameters
	params, _ := crt.Precompute(pMod, qNat)
	prmx, _ := crt.PrecomputeExtended(pMod, qNat)

	// Generate test value m = p*q
	mNat := new(saferith.Nat).Mul(p2048, q2048, 4096)
	m := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(mNat))

	b.Run("Decompose_Parallel", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeParallel(m)
			_ = mp
			_ = mq
		}
	})

	b.Run("Decompose_Serial", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeSerial(m)
			_ = mp
			_ = mq
		}
	})

	// Also benchmark recombination for comparison
	mp, mq := prmx.DecomposeSerial(m)

	b.Run("Recombine", func(b *testing.B) {
		for b.Loop() {
			result := params.Recombine(mp, mq)
			_ = result
		}
	})
}

// Benchmark with varying GOMAXPROCS for Paillier sizes
func BenchmarkDecomposePaillierGOMAXPROCS(b *testing.B) {
	// This should be run with different GOMAXPROCS values:
	// GOMAXPROCS=1 go test -bench=BenchmarkDecomposePaillierGOMAXPROCS
	// GOMAXPROCS=2 go test -bench=BenchmarkDecomposePaillierGOMAXPROCS
	// GOMAXPROCS=4 go test -bench=BenchmarkDecomposePaillierGOMAXPROCS
	// GOMAXPROCS=8 go test -bench=BenchmarkDecomposePaillierGOMAXPROCS

	p2048 := generatePrime(2048)
	q2048 := generatePrime(2048)

	// Compute modulus m = p*q
	mNat := new(saferith.Nat).Mul(p2048, q2048, 4096)
	m := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(mNat))

	pMod := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(p2048))
	qNat := (*impl.Nat)(q2048)

	// Precompute extended CRT parameters
	prmx, _ := crt.PrecomputeExtended(pMod, qNat)

	b.Run("Parallel", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeParallel(m)
			_ = mp
			_ = mq
		}
	})

	b.Run("Serial", func(b *testing.B) {
		for b.Loop() {
			mp, mq := prmx.DecomposeSerial(m)
			_ = mp
			_ = mq
		}
	})
}
