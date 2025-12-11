package modular_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// Small primes for testing - using small primes keeps tests fast
var smallOddPrimes = []uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97}

// OddPrimeFactorsGenerator generates OddPrimeFactors with random small primes p and q.
func OddPrimeFactorsGenerator() *rapid.Generator[*modular.OddPrimeFactors] {
	return rapid.Custom(func(t *rapid.T) *modular.OddPrimeFactors {
		pIdx := rapid.IntRange(0, len(smallOddPrimes)-1).Draw(t, "p_idx")
		qIdx := rapid.IntRange(0, len(smallOddPrimes)-1).Filter(func(i int) bool {
			return i != pIdx // ensure p != q
		}).Draw(t, "q_idx")

		p := numct.NewNat(smallOddPrimes[pIdx])
		q := numct.NewNat(smallOddPrimes[qIdx])

		opf, ok := modular.NewOddPrimeFactors(p, q)
		if ok != ct.True {
			t.Fatalf("failed to create OddPrimeFactors from p=%d, q=%d", smallOddPrimes[pIdx], smallOddPrimes[qIdx])
		}
		return opf
	})
}

// NatInModulusNonZero generates a non-zero Nat in the range [1, m).
func NatInModulusNonZero(m *numct.Modulus) *rapid.Generator[*numct.Nat] {
	return rapid.Custom(func(t *rapid.T) *numct.Nat {
		mVal := m.Big().Uint64()
		n := rapid.Uint64Range(1, mVal-1).Draw(t, "nat")
		return numct.NewNat(n)
	})
}

// NatInModulus generates a Nat in the range [0, m).
func NatInModulus(m *numct.Modulus) *rapid.Generator[*numct.Nat] {
	return rapid.Custom(func(t *rapid.T) *numct.Nat {
		mVal := m.Big().Uint64()
		n := rapid.Uint64Range(0, mVal-1).Draw(t, "nat")
		return numct.NewNat(n)
	})
}

// ExponentGenerator generates exponents for testing.
func ExponentGenerator() *rapid.Generator[*numct.Nat] {
	return rapid.Custom(func(t *rapid.T) *numct.Nat {
		exp := rapid.Uint64Range(0, 1000).Draw(t, "exp")
		return numct.NewNat(exp)
	})
}

// TestOddPrimeFactors_ModExp_MatchesModulus verifies CRT-based ModExp matches direct ModExp.
func TestOddPrimeFactors_ModExp_MatchesModulus(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opf := OddPrimeFactorsGenerator().Draw(t, "opf")
		base := NatInModulusNonZero(opf.Modulus()).Draw(t, "base")
		exp := ExponentGenerator().Draw(t, "exp")

		// CRT-based ModExp
		var crtResult numct.Nat
		opf.ModExp(&crtResult, base, exp)

		// Direct ModExp using Modulus
		var directResult numct.Nat
		opf.Modulus().ModExp(&directResult, base, exp)

		require.Equal(t, ct.True, crtResult.Equal(&directResult),
			"CRT ModExp != direct ModExp for base=%s, exp=%s, n=%s: got %s, want %s",
			base.Big(), exp.Big(), opf.Modulus().Big(), crtResult.Big(), directResult.Big())
	})
}

// TestOddPrimeFactors_ModExp_NonCoprimeBase tests ModExp with bases sharing factors with n.
func TestOddPrimeFactors_ModExp_NonCoprimeBase(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opf := OddPrimeFactorsGenerator().Draw(t, "opf")

		// Generate base that shares a factor with n (either p or q)
		// Pick either the p or q factor
		useP := rapid.Bool().Draw(t, "use_p")
		var factor *numct.Nat
		if useP {
			factor = opf.Params.PNat
		} else {
			factor = opf.Params.QNat
		}

		// base = k * factor for some k in [1, n/factor)
		nVal := opf.Modulus().Big().Uint64()
		factorVal := factor.Big().Uint64()
		maxK := nVal / factorVal
		if maxK < 2 {
			maxK = 2
		}
		k := rapid.Uint64Range(1, maxK-1).Draw(t, "k")
		baseVal := k * factorVal
		if baseVal >= nVal {
			baseVal = factorVal // fallback to just the factor
		}
		base := numct.NewNat(baseVal)

		exp := ExponentGenerator().Draw(t, "exp")

		// CRT-based ModExp
		var crtResult numct.Nat
		opf.ModExp(&crtResult, base, exp)

		// Direct ModExp using Modulus
		var directResult numct.Nat
		opf.Modulus().ModExp(&directResult, base, exp)

		require.Equal(t, ct.True, crtResult.Equal(&directResult),
			"CRT ModExp != direct ModExp for non-coprime base=%s, exp=%s, n=%s: got %s, want %s",
			base.Big(), exp.Big(), opf.Modulus().Big(), crtResult.Big(), directResult.Big())
	})
}

// TestOddPrimeFactors_ModInv_MatchesModulus verifies CRT-based ModInv matches direct ModInv.
func TestOddPrimeFactors_ModInv_MatchesModulus(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opf := OddPrimeFactorsGenerator().Draw(t, "opf")

		// Generate a value coprime to n (not divisible by p or q)
		a := NatInModulusNonZero(opf.Modulus()).Filter(func(x *numct.Nat) bool {
			// Filter out multiples of p or q
			pVal := opf.Params.PNat.Big().Uint64()
			qVal := opf.Params.QNat.Big().Uint64()
			xVal := x.Big().Uint64()
			return xVal%pVal != 0 && xVal%qVal != 0
		}).Draw(t, "a")

		// CRT-based ModInv
		var crtResult numct.Nat
		crtOk := opf.ModInv(&crtResult, a)

		// Direct ModInv using Modulus
		var directResult numct.Nat
		directOk := opf.Modulus().ModInv(&directResult, a)

		require.Equal(t, directOk, crtOk,
			"CRT ModInv ok != direct ModInv ok for a=%s, n=%s", a.Big(), opf.Modulus().Big())

		if crtOk == ct.True {
			require.Equal(t, ct.True, crtResult.Equal(&directResult),
				"CRT ModInv != direct ModInv for a=%s, n=%s: got %s, want %s",
				a.Big(), opf.Modulus().Big(), crtResult.Big(), directResult.Big())

			// Verify: a * inv mod n = 1
			var check numct.Nat
			opf.ModMul(&check, a, &crtResult)
			require.Equal(t, int64(1), check.Big().Int64(),
				"a * inv mod n != 1 for a=%s, inv=%s, n=%s",
				a.Big(), crtResult.Big(), opf.Modulus().Big())
		}
	})
}

// TestOddPrimeFactors_ModInv_NonInvertible_Property verifies ModInv returns false for non-invertible elements.
func TestOddPrimeFactors_ModInv_NonInvertible_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opf := OddPrimeFactorsGenerator().Draw(t, "opf")

		// Generate a value that shares a factor with n (multiple of p or q)
		useP := rapid.Bool().Draw(t, "use_p")
		var factor *numct.Nat
		if useP {
			factor = opf.Params.PNat
		} else {
			factor = opf.Params.QNat
		}

		nVal := opf.Modulus().Big().Uint64()
		factorVal := factor.Big().Uint64()
		maxK := nVal / factorVal
		if maxK < 2 {
			maxK = 2
		}
		k := rapid.Uint64Range(1, maxK-1).Draw(t, "k")
		aVal := k * factorVal
		if aVal >= nVal {
			aVal = factorVal
		}
		a := numct.NewNat(aVal)

		// CRT-based ModInv
		var crtResult numct.Nat
		crtOk := opf.ModInv(&crtResult, a)

		// Direct ModInv using Modulus
		var directResult numct.Nat
		directOk := opf.Modulus().ModInv(&directResult, a)

		require.Equal(t, directOk, crtOk,
			"CRT ModInv ok != direct ModInv ok for non-invertible a=%s, n=%s", a.Big(), opf.Modulus().Big())
		require.Equal(t, ct.False, crtOk,
			"ModInv should return false for non-invertible a=%s, n=%s", a.Big(), opf.Modulus().Big())
	})
}

// TestOddPrimeFactors_ModMul_MatchesModulus verifies CRT-based ModMul matches direct ModMul.
func TestOddPrimeFactors_ModMul_MatchesModulus(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opf := OddPrimeFactorsGenerator().Draw(t, "opf")
		a := NatInModulus(opf.Modulus()).Draw(t, "a")
		b := NatInModulus(opf.Modulus()).Draw(t, "b")

		// CRT-based ModMul
		var crtResult numct.Nat
		opf.ModMul(&crtResult, a, b)

		// Direct ModMul using Modulus
		var directResult numct.Nat
		opf.Modulus().ModMul(&directResult, a, b)

		require.Equal(t, ct.True, crtResult.Equal(&directResult),
			"CRT ModMul != direct ModMul for a=%s, b=%s, n=%s: got %s, want %s",
			a.Big(), b.Big(), opf.Modulus().Big(), crtResult.Big(), directResult.Big())
	})
}

// TestOddPrimeFactors_MultiBaseExp_MatchesModExp verifies MultiBaseExp matches individual ModExp calls.
func TestOddPrimeFactors_MultiBaseExp_MatchesModExp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opf := OddPrimeFactorsGenerator().Draw(t, "opf")
		numBases := rapid.IntRange(1, 5).Draw(t, "num_bases")

		bases := make([]*numct.Nat, numBases)
		for i := range bases {
			bases[i] = NatInModulusNonZero(opf.Modulus()).Draw(t, "base")
		}
		exp := ExponentGenerator().Draw(t, "exp")

		// MultiBaseExp
		multiResults := make([]*numct.Nat, numBases)
		for i := range multiResults {
			multiResults[i] = numct.NewNat(0)
		}
		opf.MultiBaseExp(multiResults, bases, exp)

		// Individual ModExp calls
		for i, base := range bases {
			var singleResult numct.Nat
			opf.ModExp(&singleResult, base, exp)

			require.Equal(t, ct.True, multiResults[i].Equal(&singleResult),
				"MultiBaseExp[%d] != ModExp for base=%s, exp=%s, n=%s: got %s, want %s",
				i, base.Big(), exp.Big(), opf.Modulus().Big(), multiResults[i].Big(), singleResult.Big())
		}
	})
}
