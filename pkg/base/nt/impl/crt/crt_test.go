package crt_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl/crt"
	"github.com/cronokirby/saferith"
)

// Helper to create a Nat from uint64
func natFromUint64(v uint64) *impl.Nat {
	return (*impl.Nat)(new(saferith.Nat).SetUint64(v))
}

// Helper to create a ModulusOddPrime from uint64
func modulusFromUint64(v uint64) *impl.ModulusOddPrime {
	n := new(saferith.Nat).SetUint64(v)
	return (*impl.ModulusOddPrime)(saferith.ModulusFromNat(n))
}

func TestCRTPrecompute(t *testing.T) {
	t.Parallel()

	t.Run("coprime moduli", func(t *testing.T) {
		t.Parallel()

		// Use small primes p=7, q=11
		p := modulusFromUint64(7)
		q := natFromUint64(11)

		params, ok := crt.Precompute(p, q)

		assert.Equal(t, ct.True, ok, "CRTPrecompute should succeed for coprime p and q")
		require.NotNil(t, params)

		// Verify the precomputed values
		assert.Equal(t, *p, params.P)

		// QInv should be q^{-1} mod p
		// q mod p = 11 mod 7 = 4
		// 4^{-1} mod 7 = 2 (since 4*2 = 8 ≡ 1 mod 7)
		assert.Equal(t, uint64(2), params.QInv.Uint64())
	})

	t.Run("larger coprime moduli", func(t *testing.T) {
		t.Parallel()

		// Use larger primes
		p := modulusFromUint64(97)
		q := natFromUint64(101)

		params, ok := crt.Precompute[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)

		assert.Equal(t, ct.True, ok)
		require.NotNil(t, params)

		// Verify q * qInv ≡ 1 (mod p)
		qModP := natFromUint64(0)
		p.Mod(qModP, q)

		product := natFromUint64(0)
		qInvPtr := &params.QInv
		p.ModMul(product, qModP, qInvPtr)

		assert.Equal(t, uint64(1), product.Uint64(), "q * qInv should be 1 mod p")
	})
}

func TestCRTDecompose(t *testing.T) {
	t.Parallel()

	t.Run("small moduli", func(t *testing.T) {
		t.Parallel()

		p := modulusFromUint64(7)
		q := natFromUint64(11)

		// Use PrecomputeExtended for decomposition
		prmx, ok := crt.PrecomputeExtended[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)
		require.Equal(t, ct.True, ok)

		// Test with value = 25 as a modulus
		value := modulusFromUint64(25)
		mp, mq := prmx.DecomposeSerial(value)

		// 25 mod 7 = 4
		// 25 mod 11 = 3
		assert.Equal(t, uint64(4), mp.Uint64(), "25 mod 7 should be 4")
		assert.Equal(t, uint64(3), mq.Uint64(), "25 mod 11 should be 3")
	})

	t.Run("larger values", func(t *testing.T) {
		t.Parallel()

		p := modulusFromUint64(97)
		q := natFromUint64(101)

		prmx, ok := crt.PrecomputeExtended[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)
		require.Equal(t, ct.True, ok)

		// Test with value = 1000
		value := modulusFromUint64(1000)
		mp, mq := prmx.DecomposeSerial(value)

		// 1000 mod 97 = 30
		// 1000 mod 101 = 91
		assert.Equal(t, uint64(30), mp.Uint64(), "1000 mod 97 should be 30")
		assert.Equal(t, uint64(91), mq.Uint64(), "1000 mod 101 should be 91")
	})

	t.Run("zero value", func(t *testing.T) {
		t.Parallel()

		p := modulusFromUint64(7)
		q := natFromUint64(11)

		prmx, ok := crt.PrecomputeExtended[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)
		require.Equal(t, ct.True, ok)

		// For zero, we need to use 77 (p*q) as the modulus since 0 can't be a modulus
		pNat := natFromUint64(7)
		mNat := new(saferith.Nat).Mul((*saferith.Nat)(pNat), (*saferith.Nat)(q), 128)
		// Use the product as our value to decompose
		value := (*impl.ModulusOddPrime)(saferith.ModulusFromNat(mNat))
		mp, mq := prmx.DecomposeSerial(value)

		// 77 mod 7 = 0
		// 77 mod 11 = 0
		assert.Equal(t, uint64(0), mp.Uint64())
		assert.Equal(t, uint64(0), mq.Uint64())
	})

	t.Run("parallel vs serial", func(t *testing.T) {
		t.Parallel()

		p := modulusFromUint64(97)
		q := natFromUint64(101)

		prmx, ok := crt.PrecomputeExtended[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)
		require.Equal(t, ct.True, ok)

		value := modulusFromUint64(5000)

		// Test both parallel and serial versions give same result
		mpPar, mqPar := prmx.DecomposeParallel(value)
		mpSer, mqSer := prmx.DecomposeSerial(value)

		assert.Equal(t, mpPar.Uint64(), mpSer.Uint64(), "Parallel and serial should give same mp")
		assert.Equal(t, mqPar.Uint64(), mqSer.Uint64(), "Parallel and serial should give same mq")
	})
}

func TestCRTRecombinePrecomputed(t *testing.T) {
	t.Parallel()

	t.Run("small example", func(t *testing.T) {
		t.Parallel()

		p := modulusFromUint64(7)
		q := natFromUint64(11)

		params, ok := crt.Precompute[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)
		require.Equal(t, ct.True, ok)

		// Test recombining mp=4, mq=3
		// This should give us m ≡ 4 (mod 7) and m ≡ 3 (mod 11)
		// The unique solution mod 77 is m = 25
		mp := natFromUint64(4)
		mq := natFromUint64(3)

		m := params.Recombine(mp, mq)

		assert.Equal(t, uint64(25), m.Uint64(), "CRT recombination should give 25")
	})

	t.Run("larger example", func(t *testing.T) {
		t.Parallel()

		p := modulusFromUint64(97)
		q := natFromUint64(101)

		params, ok := crt.Precompute[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)
		require.Equal(t, ct.True, ok)

		// Use residues from m = 1000
		mp := natFromUint64(30) // 1000 mod 97
		mq := natFromUint64(91) // 1000 mod 101

		m := params.Recombine(mp, mq)

		// Result should be 1000 mod (97*101) = 1000
		assert.Equal(t, uint64(1000), m.Uint64())
	})

	t.Run("identity property", func(t *testing.T) {
		t.Parallel()

		p := modulusFromUint64(13)
		q := natFromUint64(17)

		params, ok := crt.Precompute[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)
		require.Equal(t, ct.True, ok)

		// Both residues are 0
		mp := natFromUint64(0)
		mq := natFromUint64(0)

		m := params.Recombine(mp, mq)

		assert.Equal(t, uint64(0), m.Uint64())
	})
}

func TestCRTRecombineOnce(t *testing.T) {
	t.Parallel()

	t.Run("one-shot recombination", func(t *testing.T) {
		t.Parallel()

		pNat := natFromUint64(7)
		qNat := natFromUint64(11)

		mp := natFromUint64(4)
		mq := natFromUint64(3)

		m, ok := crt.Recombine[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](mp, mq, pNat, qNat)
		require.Equal(t, ct.True, ok)

		assert.Equal(t, uint64(25), m.Uint64())
	})
}

func TestCRTRoundTrip(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		p, q uint64
		m    uint64
	}{
		{"small primes", 7, 11, 25},
		{"larger primes", 13, 17, 100},
		{"consecutive primes", 23, 29, 500},
		{"with zero", 7, 11, 77}, // Use p*q for zero case
		{"with one", 7, 11, 1},
		{"max in range", 7, 11, 76}, // 77-1
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := modulusFromUint64(tc.p)
			q := natFromUint64(tc.q)

			// Precompute CRT parameters with extended params for decomposition
			prmx, ok := crt.PrecomputeExtended[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)
			require.Equal(t, ct.True, ok)

			// Original value as modulus
			m := modulusFromUint64(tc.m)

			// Decompose
			mp, mq := prmx.DecomposeSerial(m)

			// Recombine
			mRecovered := prmx.Recombine(mp, mq)

			// Should recover m mod (p*q)
			expected := tc.m % (tc.p * tc.q)
			assert.Equal(t, uint64(expected), mRecovered.Uint64(),
				"Round trip should preserve value mod p*q")
		})
	}
}

func TestCRTConsistency(t *testing.T) {
	t.Parallel()

	// Test that precomputed and one-shot give the same results
	p := modulusFromUint64(31)
	q := natFromUint64(37)

	params, ok := crt.Precompute[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](p, q)
	require.Equal(t, ct.True, ok)

	testValues := []uint64{0, 1, 10, 100, 500, 1000}

	for _, val := range testValues {
		mp := natFromUint64(val % 31)
		mq := natFromUint64(val % 37)

		mPrecomputed := params.Recombine(mp, mq)

		pNat := natFromUint64(31)
		qNat := natFromUint64(37)
		mOnce, ok2 := crt.Recombine[*impl.ModulusOddPrime, *impl.Nat, impl.ModulusOddPrime, impl.Nat](mp, mq, pNat, qNat)
		require.Equal(t, ct.True, ok2)

		assert.Equal(t, mPrecomputed.Uint64(), mOnce.Uint64(),
			"Precomputed and one-shot should give same result for value %d", val)
	}
}

func TestCRTBasicRecombine(t *testing.T) {
	// Test basic CRT recombination
	p := big.NewInt(11)
	q := big.NewInt(13)

	// Choose residues
	rp := big.NewInt(3) // x ≡ 3 (mod 11)
	rq := big.NewInt(7) // x ≡ 7 (mod 13)

	// Expected result: x = 59 (can verify: 59 % 11 = 4, 59 % 13 = 7)
	// Actually checking: CRT(3, 7, 11, 13) = 59

	// Convert to impl types
	pNat := (*impl.Nat)(new(saferith.Nat).SetBig(p, 64).Resize(64))
	qNat := (*impl.Nat)(new(saferith.Nat).SetBig(q, 64).Resize(64))
	rpNat := (*impl.Nat)(new(saferith.Nat).SetBig(rp, 64).Resize(64))
	rqNat := (*impl.Nat)(new(saferith.Nat).SetBig(rq, 64).Resize(64))

	// Perform CRT recombination using the correct signature
	// Recombine expects: mp, mq (residues), p, q (moduli as Nats)
	result, ok := crt.Recombine[*impl.ModulusOddPrime, *impl.Nat](rpNat, rqNat, pNat, qNat)
	assert.Equal(t, ct.True, ok, "CRT recombination should succeed")

	// Verify result
	resultBig := new(big.Int).SetBytes(result.Bytes())

	// Check the residues are correct
	checkP := new(big.Int).Mod(resultBig, p)
	checkQ := new(big.Int).Mod(resultBig, q)

	assert.Equal(t, 0, rp.Cmp(checkP), "Result mod p should match residue")
	assert.Equal(t, 0, rq.Cmp(checkQ), "Result mod q should match residue")

	t.Logf("CRT(%v, %v, %v, %v) = %v", rp, rq, p, q, resultBig)
}

func TestCRTPrecomputedParams(t *testing.T) {
	// Test precomputed CRT for efficiency
	pBig, _ := rand.Prime(rand.Reader, 128)
	qBig, _ := rand.Prime(rand.Reader, 128)

	// Convert to impl types
	p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, 128).Resize(128))
	q := (*impl.Nat)(new(saferith.Nat).SetBig(qBig, 128).Resize(128))

	// Create modulus from p
	var pMod impl.ModulusOddPrime
	ok1 := pMod.SetNat(p)
	assert.Equal(t, ct.True, ok1, "Creating modulus should succeed")

	// Precompute CRT parameters
	params, ok := crt.Precompute[*impl.ModulusOddPrime, *impl.Nat](&pMod, q)
	assert.Equal(t, ct.True, ok, "Precomputation should succeed")

	// Test multiple recombinations with same parameters
	for i := 0; i < 10; i++ {
		// Generate random residues
		rpBig, _ := rand.Int(rand.Reader, pBig)
		rqBig, _ := rand.Int(rand.Reader, qBig)

		rp := (*impl.Nat)(new(saferith.Nat).SetBig(rpBig, 128).Resize(128))
		rq := (*impl.Nat)(new(saferith.Nat).SetBig(rqBig, 128).Resize(128))

		// Recombine using precomputed params
		result := params.Recombine(rp, rq)

		// Verify result
		resultBig := new(big.Int).SetBytes(result.Bytes())
		n := new(big.Int).Mul(pBig, qBig)

		// Check residues
		checkP := new(big.Int).Mod(resultBig, pBig)
		checkQ := new(big.Int).Mod(resultBig, qBig)

		assert.Equal(t, 0, rpBig.Cmp(checkP), "Result mod p should match residue")
		assert.Equal(t, 0, rqBig.Cmp(checkQ), "Result mod q should match residue")
		assert.Equal(t, -1, resultBig.Cmp(n), "Result should be less than n")
	}
}

func TestCRTMultiFactor(t *testing.T) {
	// Test multi-factor CRT with 3 primes
	primes := make([]*big.Int, 3)
	primes[0] = big.NewInt(7)
	primes[1] = big.NewInt(11)
	primes[2] = big.NewInt(13)

	// Residues: x ≡ 2 (mod 7), x ≡ 3 (mod 11), x ≡ 4 (mod 13)
	residuesBig := []*big.Int{
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
	}

	// Convert to impl types
	factors := make([]*impl.Nat, 3)
	residues := make([]*impl.Nat, 3)

	for i := 0; i < 3; i++ {
		factors[i] = (*impl.Nat)(new(saferith.Nat).SetBig(primes[i], 64).Resize(64))
		residues[i] = (*impl.Nat)(new(saferith.Nat).SetBig(residuesBig[i], 64).Resize(64))
	}

	// Precompute multi-factor CRT
	// MM is for the composite modulus, MF is for the factors
	params, ok := crt.PrecomputeMulti[*impl.ModulusOdd, *impl.ModulusOddPrime, *impl.Nat](factors...)
	assert.Equal(t, ct.True, ok, "Multi-factor precomputation should succeed")

	// Recombine
	result, ok := params.Recombine(residues)
	assert.Equal(t, ct.True, ok, "Multi-factor recombination should succeed")

	// Verify result
	resultBig := new(big.Int).SetBytes(result.Bytes())

	// Verify residues
	for i := 0; i < 3; i++ {
		check := new(big.Int).Mod(resultBig, primes[i])
		assert.Equal(t, 0, residuesBig[i].Cmp(check), "Result mod p[%d] should match residue", i)
	}

	t.Logf("Multi-factor CRT result: %v", resultBig)
}

func BenchmarkCRTOperations(b *testing.B) {
	// Benchmark CRT with different sizes
	sizes := []int{256, 512, 1024, 2048}

	for _, bits := range sizes {
		b.Run(fmt.Sprintf("%d-bit", bits), func(b *testing.B) {
			// Generate primes
			pBig, _ := rand.Prime(rand.Reader, bits)
			qBig, _ := rand.Prime(rand.Reader, bits)

			p := (*impl.Nat)(new(saferith.Nat).SetBig(pBig, bits).Resize(bits))
			q := (*impl.Nat)(new(saferith.Nat).SetBig(qBig, bits).Resize(bits))

			var pMod impl.ModulusOddPrime
			pMod.SetNat(p)

			// Precompute
			params, _ := crt.Precompute[*impl.ModulusOddPrime, *impl.Nat](&pMod, q)

			// Random residues
			rpBig, _ := rand.Int(rand.Reader, pBig)
			rqBig, _ := rand.Int(rand.Reader, qBig)
			rp := (*impl.Nat)(new(saferith.Nat).SetBig(rpBig, bits).Resize(bits))
			rq := (*impl.Nat)(new(saferith.Nat).SetBig(rqBig, bits).Resize(bits))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = params.Recombine(rp, rq)
			}
		})
	}
}
