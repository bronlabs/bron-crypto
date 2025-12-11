package modular_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// OddPrimeSquareFactorsGenerator generates OddPrimeSquareFactors with random small primes p and q.
func OddPrimeSquareFactorsGenerator() *rapid.Generator[*modular.OddPrimeSquareFactors] {
	return rapid.Custom(func(t *rapid.T) *modular.OddPrimeSquareFactors {
		pIdx := rapid.IntRange(0, len(smallOddPrimes)-1).Draw(t, "p_idx")
		qIdx := rapid.IntRange(0, len(smallOddPrimes)-1).Filter(func(i int) bool {
			return i != pIdx // ensure p != q
		}).Draw(t, "q_idx")

		p := numct.NewNat(smallOddPrimes[pIdx])
		q := numct.NewNat(smallOddPrimes[qIdx])

		opsf, ok := modular.NewOddPrimeSquareFactors(p, q)
		if ok != ct.True {
			t.Fatalf("failed to create OddPrimeSquareFactors from p=%d, q=%d", smallOddPrimes[pIdx], smallOddPrimes[qIdx])
		}
		return opsf
	})
}

// TestOddPrimeSquareFactors_ModExp_MatchesModulus verifies CRT-based ModExp matches direct ModExp.
func TestOddPrimeSquareFactors_ModExp_MatchesModulus(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opsf := OddPrimeSquareFactorsGenerator().Draw(t, "opsf")
		base := NatInModulusNonZero(opsf.Modulus()).Draw(t, "base")
		exp := ExponentGenerator().Draw(t, "exp")

		// CRT-based ModExp
		var crtResult numct.Nat
		opsf.ModExp(&crtResult, base, exp)

		// Direct ModExp using Modulus
		var directResult numct.Nat
		opsf.Modulus().ModExp(&directResult, base, exp)

		require.Equal(t, ct.True, crtResult.Equal(&directResult),
			"CRT ModExp != direct ModExp for base=%s, exp=%s, n²=%s: got %s, want %s",
			base.Big(), exp.Big(), opsf.Modulus().Big(), crtResult.Big(), directResult.Big())
	})
}

// TestOddPrimeSquareFactors_ModExp_NonCoprimeBase tests ModExp with bases sharing factors with n.
func TestOddPrimeSquareFactors_ModExp_NonCoprimeBase(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opsf := OddPrimeSquareFactorsGenerator().Draw(t, "opsf")

		// Generate base that shares a factor with n (either p or q)
		useP := rapid.Bool().Draw(t, "use_p")
		var factor *numct.Nat
		if useP {
			factor = opsf.P.Factor.Nat()
		} else {
			factor = opsf.Q.Factor.Nat()
		}

		// base = k * factor for some k in [1, n²/factor)
		n2Val := opsf.Modulus().Big().Uint64()
		factorVal := factor.Big().Uint64()
		maxK := n2Val / factorVal
		maxK = max(maxK, 2)
		// Limit maxK to avoid overflow
		maxK = min(maxK, 10000)
		k := rapid.Uint64Range(1, maxK-1).Draw(t, "k")
		baseVal := k * factorVal
		if baseVal >= n2Val {
			baseVal = factorVal // fallback to just the factor
		}
		base := numct.NewNat(baseVal)

		exp := ExponentGenerator().Draw(t, "exp")

		// CRT-based ModExp
		var crtResult numct.Nat
		opsf.ModExp(&crtResult, base, exp)

		// Direct ModExp using Modulus
		var directResult numct.Nat
		opsf.Modulus().ModExp(&directResult, base, exp)

		require.Equal(t, ct.True, crtResult.Equal(&directResult),
			"CRT ModExp != direct ModExp for non-coprime base=%s, exp=%s, n²=%s: got %s, want %s",
			base.Big(), exp.Big(), opsf.Modulus().Big(), crtResult.Big(), directResult.Big())
	})
}

// TestOddPrimeSquareFactors_ModInv_MatchesModulus verifies CRT-based ModInv matches direct ModInv.
func TestOddPrimeSquareFactors_ModInv_MatchesModulus(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opsf := OddPrimeSquareFactorsGenerator().Draw(t, "opsf")

		// Generate a value coprime to n² (not divisible by p or q)
		a := NatInModulusNonZero(opsf.Modulus()).Filter(func(x *numct.Nat) bool {
			// Filter out multiples of p or q
			pVal := opsf.P.Factor.Nat().Big().Uint64()
			qVal := opsf.Q.Factor.Nat().Big().Uint64()
			xVal := x.Big().Uint64()
			return xVal%pVal != 0 && xVal%qVal != 0
		}).Draw(t, "a")

		// CRT-based ModInv (uses N2.ModInv directly)
		var crtResult numct.Nat
		crtOk := opsf.ModInv(&crtResult, a)

		// Direct ModInv using Modulus
		var directResult numct.Nat
		directOk := opsf.Modulus().ModInv(&directResult, a)

		require.Equal(t, directOk, crtOk,
			"ModInv ok mismatch for a=%s, n²=%s", a.Big(), opsf.Modulus().Big())

		if crtOk == ct.True {
			require.Equal(t, ct.True, crtResult.Equal(&directResult),
				"ModInv != direct ModInv for a=%s, n²=%s: got %s, want %s",
				a.Big(), opsf.Modulus().Big(), crtResult.Big(), directResult.Big())

			// Verify: a * inv mod n² = 1
			var check numct.Nat
			opsf.ModMul(&check, a, &crtResult)
			require.Equal(t, int64(1), check.Big().Int64(),
				"a * inv mod n² != 1 for a=%s, inv=%s, n²=%s",
				a.Big(), crtResult.Big(), opsf.Modulus().Big())
		}
	})
}

// TestOddPrimeSquareFactors_ModInv_NonInvertible_Property verifies ModInv returns false for non-invertible elements.
func TestOddPrimeSquareFactors_ModInv_NonInvertible_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opsf := OddPrimeSquareFactorsGenerator().Draw(t, "opsf")

		// Generate a value that shares a factor with n (multiple of p or q)
		useP := rapid.Bool().Draw(t, "use_p")
		var factor *numct.Nat
		if useP {
			factor = opsf.P.Factor.Nat()
		} else {
			factor = opsf.Q.Factor.Nat()
		}

		n2Val := opsf.Modulus().Big().Uint64()
		factorVal := factor.Big().Uint64()
		maxK := n2Val / factorVal
		maxK = max(maxK, 2)
		maxK = min(maxK, 10000)
		k := rapid.Uint64Range(1, maxK-1).Draw(t, "k")
		aVal := k * factorVal
		if aVal >= n2Val {
			aVal = factorVal
		}
		a := numct.NewNat(aVal)

		// ModInv
		var result numct.Nat
		ok := opsf.ModInv(&result, a)

		// Direct ModInv using Modulus
		var directResult numct.Nat
		directOk := opsf.Modulus().ModInv(&directResult, a)

		require.Equal(t, directOk, ok,
			"ModInv ok mismatch for non-invertible a=%s, n²=%s", a.Big(), opsf.Modulus().Big())
		require.Equal(t, ct.False, ok,
			"ModInv should return false for non-invertible a=%s, n²=%s", a.Big(), opsf.Modulus().Big())
	})
}

// TestOddPrimeSquareFactors_ModMul_MatchesModulus verifies ModMul matches direct ModMul.
func TestOddPrimeSquareFactors_ModMul_MatchesModulus(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opsf := OddPrimeSquareFactorsGenerator().Draw(t, "opsf")
		a := NatInModulus(opsf.Modulus()).Draw(t, "a")
		b := NatInModulus(opsf.Modulus()).Draw(t, "b")

		// ModMul (uses N2.ModMul directly)
		var result numct.Nat
		opsf.ModMul(&result, a, b)

		// Direct ModMul using Modulus
		var directResult numct.Nat
		opsf.Modulus().ModMul(&directResult, a, b)

		require.Equal(t, ct.True, result.Equal(&directResult),
			"ModMul != direct ModMul for a=%s, b=%s, n²=%s: got %s, want %s",
			a.Big(), b.Big(), opsf.Modulus().Big(), result.Big(), directResult.Big())
	})
}

// TestOddPrimeSquareFactors_MultiBaseExp_MatchesModExp verifies MultiBaseExp matches individual ModExp calls.
func TestOddPrimeSquareFactors_MultiBaseExp_MatchesModExp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opsf := OddPrimeSquareFactorsGenerator().Draw(t, "opsf")
		numBases := rapid.IntRange(1, 5).Draw(t, "num_bases")

		bases := make([]*numct.Nat, numBases)
		for i := range bases {
			bases[i] = NatInModulusNonZero(opsf.Modulus()).Draw(t, "base")
		}
		exp := ExponentGenerator().Draw(t, "exp")

		// MultiBaseExp
		multiResults := make([]*numct.Nat, numBases)
		for i := range multiResults {
			multiResults[i] = numct.NewNat(0)
		}
		opsf.MultiBaseExp(multiResults, bases, exp)

		// Individual ModExp calls
		for i, base := range bases {
			var singleResult numct.Nat
			opsf.ModExp(&singleResult, base, exp)

			require.Equal(t, ct.True, multiResults[i].Equal(&singleResult),
				"MultiBaseExp[%d] != ModExp for base=%s, exp=%s, n²=%s: got %s, want %s",
				i, base.Big(), exp.Big(), opsf.Modulus().Big(), multiResults[i].Big(), singleResult.Big())
		}
	})
}

// TestOddPrimeSquareFactors_ExpToN_MatchesModExp verifies ExpToN matches ModExp with exponent n.
func TestOddPrimeSquareFactors_ExpToN_MatchesModExp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		opsf := OddPrimeSquareFactorsGenerator().Draw(t, "opsf")
		a := NatInModulusNonZero(opsf.Modulus()).Draw(t, "a")

		// Get n from CrtModN
		n := opsf.CrtModN.Modulus().Nat()

		// ExpToN
		var expToNResult numct.Nat
		opsf.ExpToN(&expToNResult, a)

		// Direct ModExp with exponent n
		var directResult numct.Nat
		opsf.Modulus().ModExp(&directResult, a, n)

		require.Equal(t, ct.True, expToNResult.Equal(&directResult),
			"ExpToN != ModExp(a, n) for a=%s, n=%s, n²=%s: got %s, want %s",
			a.Big(), n.Big(), opsf.Modulus().Big(), expToNResult.Big(), directResult.Big())
	})
}
