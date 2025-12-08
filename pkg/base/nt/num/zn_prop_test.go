package num_test

import (
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func UintGeneratorGivenModulus(t *testing.T, modulus *num.NatPlus) *rapid.Generator[*num.Uint] {
	return rapid.Custom(func(rt *rapid.T) *num.Uint {
		zMod, err := num.NewZMod(modulus)
		require.NoError(t, err)
		n := rapid.Uint64Max(modulus.Uint64()-1).Draw(rt, "n")
		out := zMod.FromUint64(n)
		return out
	})
}

func UintGenerator(t *testing.T) (generator *rapid.Generator[*num.Uint], modulus *num.NatPlus) {
	lo, err := num.NPlus().FromUint64(1)
	require.NoError(t, err)
	hi, err := num.NPlus().FromUint64(1 << 16)
	require.NoError(t, err)
	modulus, err = num.NPlus().Random(lo, hi, pcg.NewRandomised())
	require.NoError(t, err)
	return UintGeneratorGivenModulus(t, modulus), modulus
}

func TestUintLikeProperties(t *testing.T) {
	t.Parallel()
	g, modulus := UintGenerator(t)
	zMod, err := num.NewZMod(modulus)
	require.NoError(t, err)
	suite := properties.ZModLike(t, zMod, g)
	suite.Check(t)
}

func TestZMod_FromBigRoundTrip_Property(t *testing.T) {
	t.Parallel()
	g, modulus := UintGenerator(t)
	zMod, err := num.NewZMod(modulus)
	require.NoError(t, err)
	FromBigRoundTrip_Property(t, zMod, g)
}

func TestZMod_FromNatPlus_Property(t *testing.T) {
	t.Parallel()
	_, modulus := UintGenerator(t)
	zMod, err := num.NewZMod(modulus)
	require.NoError(t, err)
	rapid.Check(t, func(rt *rapid.T) {
		n := NatPlusGenerator(t).Draw(rt, "n")
		elem, err := zMod.FromNatPlus(n)
		require.NoError(t, err)
		// FromNatPlus should reduce the value modulo the modulus
		expected := new(big.Int).Mod(n.Big(), modulus.Big())
		require.Equal(t, 0, elem.Big().Cmp(expected), "expected %v, got %v", expected, elem.Big())
	})
}

func TestZMod_FromNat_Property(t *testing.T) {
	t.Parallel()
	_, modulus := UintGenerator(t)
	zMod, err := num.NewZMod(modulus)
	require.NoError(t, err)
	rapid.Check(t, func(rt *rapid.T) {
		n := NatGenerator(t).Draw(rt, "n")
		elem, err := zMod.FromNat(n)
		require.NoError(t, err)
		// FromNat should reduce the value modulo the modulus
		expected := new(big.Int).Mod(n.Big(), modulus.Big())
		require.Equal(t, 0, elem.Big().Cmp(expected), "expected %v, got %v", expected, elem.Big())
	})
}

func TestZMod_FromInt_Property(t *testing.T) {
	t.Parallel()
	_, modulus := UintGenerator(t)
	zMod, err := num.NewZMod(modulus)
	require.NoError(t, err)
	rapid.Check(t, func(rt *rapid.T) {
		n := IntGenerator(t).Draw(rt, "n")
		elem, err := zMod.FromInt(n)
		require.NoError(t, err)
		// FromInt should reduce the value modulo the modulus
		expected := new(big.Int).Mod(n.Big(), modulus.Big())
		require.Equal(t, 0, elem.Big().Cmp(expected), "expected %v, got %v", expected, elem.Big())
	})
}

func TestZMod_FromRat_Property(t *testing.T) {
	t.Parallel()
	_, modulus := UintGenerator(t)
	zMod, err := num.NewZMod(modulus)
	require.NoError(t, err)
	rapid.Check(t, func(rt *rapid.T) {
		r := SmallRatGenerator(t).Draw(rt, "r")
		elem, err := zMod.FromRat(r)
		if err != nil {
			// FromRat can fail if the denominator is not coprime with the modulus
			return
		}
		// FromRat computes (numerator * denominator^-1) mod modulus
		// Verify: elem * denominator == numerator (mod modulus)
		denom, err := zMod.FromNatPlus(r.Denominator())
		require.NoError(t, err)
		product := elem.Mul(denom)
		expectedNumerator := new(big.Int).Mod(r.Numerator().Big(), modulus.Big())
		require.Equal(t, 0, product.Big().Cmp(expectedNumerator), "elem * denom should equal numerator mod modulus")
	})
}

func TestZMod_HashCodeEqualityCorrespondence_Property(t *testing.T) {
	t.Parallel()
	g, _ := UintGenerator(t)
	HashCodeEqualityCorrespondence_Property(t, g)
}

func TestZMod_Lsh_Property(t *testing.T) {
	t.Parallel()
	g, modulus := UintGenerator(t)
	rapid.Check(t, func(rt *rapid.T) {
		n := g.Draw(rt, "n")
		shift := rapid.IntRange(0, 16).Draw(rt, "shift")
		lsh := n.Lsh(uint(shift))
		// Lsh should be equivalent to multiplying by 2^shift mod modulus
		multiplier := new(big.Int).Lsh(big.NewInt(1), uint(shift))
		expected := new(big.Int).Mul(n.Big(), multiplier)
		expected.Mod(expected, modulus.Big())
		require.Equal(t, 0, lsh.Big().Cmp(expected), "Lsh(%d) should equal n * 2^%d mod modulus", shift, shift)
	})
}

func TestZMod_Rsh_Property(t *testing.T) {
	t.Parallel()
	g, modulus := UintGenerator(t)
	rapid.Check(t, func(rt *rapid.T) {
		n := g.Draw(rt, "n")
		shift := rapid.IntRange(0, 16).Draw(rt, "shift")
		rsh := n.Rsh(uint(shift))
		// Rsh should be equivalent to floor division by 2^shift, then mod modulus
		divisor := new(big.Int).Lsh(big.NewInt(1), uint(shift))
		expected := new(big.Int).Div(n.Big(), divisor)
		expected.Mod(expected, modulus.Big())
		require.Equal(t, 0, rsh.Big().Cmp(expected), "Rsh(%d) should equal n / 2^%d mod modulus", shift, shift)
	})
}

func TestZMod_EuclideanDiv_Property(t *testing.T) {
	t.Parallel()
	// Use a prime modulus so EuclideanDiv works (requires IsSemiDomain)
	primeModulus, err := num.NPlus().FromUint64(65537) // Fermat prime F4
	require.NoError(t, err)
	g := UintGeneratorGivenModulus(t, primeModulus)

	rapid.Check(t, func(rt *rapid.T) {
		a := g.Draw(rt, "a")
		b := g.Draw(rt, "b")

		if b.IsZero() {
			// Division by zero should fail
			_, _, err := a.EuclideanDiv(b)
			require.Error(t, err)
			return
		}

		quot, rem, err := a.EuclideanDiv(b)
		require.NoError(t, err)

		// Property: a == quot * b + rem
		product := quot.Mul(b)
		reconstructed := product.Add(rem)
		require.Equal(t, 0, a.Big().Cmp(reconstructed.Big()), "a should equal quot * b + rem")

		// Property: EuclideanValuation(rem) < EuclideanValuation(b) or rem == 0
		if !rem.IsZero() {
			remVal := rem.EuclideanValuation()
			bVal := b.EuclideanValuation()
			// rem < b means remVal < bVal (strict inequality)
			require.True(t, remVal.IsLessThanOrEqual(bVal) && remVal.Big().Cmp(bVal.Big()) != 0,
				"remainder's valuation should be less than divisor's valuation")
		}
	})
}

func TestZMod_Exp_Property(t *testing.T) {
	t.Parallel()
	g, modulus := UintGenerator(t)

	rapid.Check(t, func(rt *rapid.T) {
		base := g.Draw(rt, "base")
		exp := rapid.Uint64Range(0, 20).Draw(rt, "exp")
		expNat := num.N().FromUint64(exp)

		result := base.Exp(expNat)

		// Verify against big.Int exponentiation
		expected := new(big.Int).Exp(base.Big(), big.NewInt(int64(exp)), modulus.Big())
		require.Equal(t, 0, result.Big().Cmp(expected), "base^exp mod modulus mismatch")
	})
}

func TestZMod_Exp_ZeroExponent_Property(t *testing.T) {
	t.Parallel()
	g, _ := UintGenerator(t)

	rapid.Check(t, func(rt *rapid.T) {
		base := g.Draw(rt, "base")
		zeroExp := num.N().FromUint64(0)

		result := base.Exp(zeroExp)

		// x^0 == 1 for any x
		require.True(t, result.IsOne(), "x^0 should equal 1")
	})
}

func TestZMod_Exp_OneExponent_Property(t *testing.T) {
	t.Parallel()
	g, _ := UintGenerator(t)

	rapid.Check(t, func(rt *rapid.T) {
		base := g.Draw(rt, "base")
		oneExp := num.N().FromUint64(1)

		result := base.Exp(oneExp)

		// x^1 == x
		require.Equal(t, 0, result.Big().Cmp(base.Big()), "x^1 should equal x")
	})
}

func TestZMod_Exp_Multiplication_Property(t *testing.T) {
	t.Parallel()
	g, _ := UintGenerator(t)

	rapid.Check(t, func(rt *rapid.T) {
		base := g.Draw(rt, "base")
		exp1 := rapid.Uint64Range(0, 10).Draw(rt, "exp1")
		exp2 := rapid.Uint64Range(0, 10).Draw(rt, "exp2")

		exp1Nat := num.N().FromUint64(exp1)
		exp2Nat := num.N().FromUint64(exp2)
		sumExpNat := num.N().FromUint64(exp1 + exp2)

		// Property: x^a * x^b == x^(a+b)
		result1 := base.Exp(exp1Nat)
		result2 := base.Exp(exp2Nat)
		product := result1.Mul(result2)

		resultSum := base.Exp(sumExpNat)

		require.Equal(t, 0, product.Big().Cmp(resultSum.Big()), "x^a * x^b should equal x^(a+b)")
	})
}

func TestZMod_ExpI_Property(t *testing.T) {
	t.Parallel()
	// Use a prime modulus so modular inverse exists for non-zero elements
	primeModulus, err := num.NPlus().FromUint64(65537)
	require.NoError(t, err)
	g := UintGeneratorGivenModulus(t, primeModulus)

	rapid.Check(t, func(rt *rapid.T) {
		base := g.Draw(rt, "base")
		exp := rapid.Int64Range(-20, 20).Draw(rt, "exp")
		expInt := num.Z().FromInt64(exp)

		if base.IsZero() && exp < 0 {
			// Can't compute inverse of zero
			return
		}

		result := base.ExpI(expInt)

		// For positive exponents, should match regular Exp
		if exp >= 0 {
			expNat := num.N().FromUint64(uint64(exp))
			expected := base.Exp(expNat)
			require.Equal(t, 0, result.Big().Cmp(expected.Big()), "ExpI with positive exp should match Exp")
		} else {
			// For negative exponents: base^(-n) == (base^(-1))^n
			// Verify: result * base^|exp| == 1
			absExp := num.N().FromUint64(uint64(-exp))
			basePowAbs := base.Exp(absExp)
			product := result.Mul(basePowAbs)
			require.True(t, product.IsOne(), "base^(-n) * base^n should equal 1")
		}
	})
}

func TestZMod_ExpI_NegativeExponent_Property(t *testing.T) {
	t.Parallel()
	// Use a prime modulus so modular inverse exists
	primeModulus, err := num.NPlus().FromUint64(65537)
	require.NoError(t, err)
	g := UintGeneratorGivenModulus(t, primeModulus)

	rapid.Check(t, func(rt *rapid.T) {
		base := g.Draw(rt, "base")
		if base.IsZero() {
			return // Skip zero base
		}

		exp := rapid.Int64Range(1, 10).Draw(rt, "exp")
		posExpInt := num.Z().FromInt64(exp)
		negExpInt := num.Z().FromInt64(-exp)

		// Property: base^n * base^(-n) == 1
		posResult := base.ExpI(posExpInt)
		negResult := base.ExpI(negExpInt)
		product := posResult.Mul(negResult)
		require.True(t, product.IsOne(), "base^n * base^(-n) should equal 1")
	})
}

func TestZMod_ExpBounded_Property(t *testing.T) {
	t.Parallel()
	g, modulus := UintGenerator(t)

	rapid.Check(t, func(rt *rapid.T) {
		base := g.Draw(rt, "base")
		exp := rapid.Uint64Range(0, 1000).Draw(rt, "exp")
		bits := rapid.UintRange(1, 16).Draw(rt, "bits")

		expNat := num.N().FromUint64(exp)
		result := base.ExpBounded(expNat, bits)

		// ExpBounded uses only the lower 'bits' bits of the exponent
		mask := (uint64(1) << bits) - 1
		boundedExp := exp & mask
		boundedExpNat := num.N().FromUint64(boundedExp)

		// Verify against big.Int
		expected := new(big.Int).Exp(base.Big(), big.NewInt(int64(boundedExp)), modulus.Big())
		require.Equal(t, 0, result.Big().Cmp(expected), "ExpBounded should use only lower %d bits", bits)

		// Also verify it matches Exp with bounded exponent
		expectedFromExp := base.Exp(boundedExpNat)
		require.Equal(t, 0, result.Big().Cmp(expectedFromExp.Big()), "ExpBounded should match Exp with masked exponent")
	})
}

func TestZMod_ExpIBounded_Property(t *testing.T) {
	t.Parallel()
	// Use a prime modulus so modular inverse exists
	primeModulus, err := num.NPlus().FromUint64(65537)
	require.NoError(t, err)
	g := UintGeneratorGivenModulus(t, primeModulus)

	rapid.Check(t, func(rt *rapid.T) {
		base := g.Draw(rt, "base")
		exp := rapid.Int64Range(-1000, 1000).Draw(rt, "exp")
		bits := rapid.UintRange(1, 16).Draw(rt, "bits")

		if base.IsZero() && exp < 0 {
			return // Can't compute inverse of zero
		}

		expInt := num.Z().FromInt64(exp)
		result := base.ExpIBounded(expInt, bits)

		// ExpIBounded uses only the lower 'bits' bits of the exponent magnitude
		mask := int64((uint64(1) << bits) - 1)
		var boundedExp int64
		if exp >= 0 {
			boundedExp = exp & mask
		} else {
			boundedExp = -((-exp) & mask)
		}

		// Verify it matches ExpI with bounded exponent
		boundedExpInt := num.Z().FromInt64(boundedExp)
		expectedFromExpI := base.ExpI(boundedExpInt)
		require.Equal(t, 0, result.Big().Cmp(expectedFromExpI.Big()), "ExpIBounded should match ExpI with masked exponent")
	})
}
