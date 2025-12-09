package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func IntGenerator(t *testing.T) *rapid.Generator[*num.Int] {
	return rapid.Custom(func(t *rapid.T) *num.Int {
		n := rapid.Int64().Draw(t, "n")
		return num.Z().FromInt64(n)
	})
}

func SmallIntGenerator(t *testing.T) *rapid.Generator[*num.Int] {
	return rapid.Custom(func(t *rapid.T) *num.Int {
		n := rapid.Int16().Draw(t, "n")
		return num.Z().FromInt64(int64(n))
	})
}

func TestZLikeProperties(t *testing.T) {
	t.Parallel()
	suite := properties.ZLike(t, num.Z(), IntGenerator(t))
	suite.Check(t)
}

func TestZ_FromBigRoundTrip_Property(t *testing.T) {
	t.Parallel()
	FromBigRoundTrip_Property(t, num.Z(), IntGenerator(t))
}

func TestZ_FromNatPlus_Property(t *testing.T) {
	t.Parallel()
	FromNatPlusRoundTrip_Property(t, num.Z(), NatPlusGenerator(t))
}

func TestZ_FromNat_Property(t *testing.T) {
	t.Parallel()
	FromNatRoundTrip_Property(t, num.Z(), NatGenerator(t), true)
}

func TestZ_FromRat_Property(t *testing.T) {
	t.Parallel()
	FromRatRoundTrip_Property(t, num.Z(), SmallRatGenerator(t), true, true)
}

func TestZ_HashCodeEqualityCorrespondence_Property(t *testing.T) {
	t.Parallel()
	HashCodeEqualityCorrespondence_Property(t, IntGenerator(t))
}

func TestZ_LshRshRoundTrip_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := IntGenerator(t).Draw(rt, "n")
		shift := rapid.Uint8().Draw(rt, "shift")
		lsh := n.Lsh(uint(shift))
		rsh := lsh.Rsh(uint(shift))
		require.True(t, n.Equal(rsh))
	})
}

func TestZ_WithinRange_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := IntGenerator(t).Draw(rt, "n")
		modulus := NatPlusGenerator(t).Draw(rt, "modulus")
		expected := !n.IsNegative() && n.Compare(modulus.Lift()).IsLessThan()
		actual := n.IsInRange(modulus)
		require.Equal(t, expected, actual)
	})
}

func TestZ_IncrementDecrement_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := IntGenerator(t).Draw(rt, "n")
		shouldBeN := n.Increment().Decrement()
		require.True(t, n.Equal(shouldBeN))
	})
}

func TestZ_TryDiv_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		divisor := rapid.Int64Range(-1000, 1000).Filter(func(n int64) bool { return n != 0 }).Draw(rt, "divisor")
		multiplier := rapid.Int64Range(-1000, 1000).Draw(rt, "multiplier")

		d := num.Z().FromInt64(divisor)
		m := num.Z().FromInt64(multiplier)

		dividend := d.Mul(m)
		result, err := dividend.TryDivVarTime(d)
		require.NoError(t, err)
		require.True(t, m.Equal(result), "expected %v, got %v", m.Big(), result.Big())
	})
}

func TestZ_TryDiv_DivisionByZero_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := IntGenerator(t).Draw(rt, "n")
		zero := num.Z().FromInt64(0)
		_, err := n.TryDivVarTime(zero)
		require.Error(t, err)
	})
}

func TestZ_TryDiv_InexactDivision_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		dividend := rapid.Int64Range(-1000, 1000).Draw(rt, "dividend")
		divisor := rapid.Int64Range(2, 1000).Draw(rt, "divisor")
		remainder := rapid.Int64Range(1, divisor-1).Draw(rt, "remainder")

		d := num.Z().FromInt64(dividend*divisor + remainder)
		div := num.Z().FromInt64(divisor)

		_, err := d.TryDivVarTime(div)
		require.Error(t, err)
	})
}

func TestZ_TryInv_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := IntGenerator(t).Draw(rt, "n")
		result, err := n.TryInv()

		absN := n.Abs()
		if absN.IsOne() {
			require.NoError(t, err)
			require.True(t, n.Equal(result), "inverse of ±1 should be itself")
		} else {
			require.Error(t, err)
		}
	})
}

func TestZ_TryInv_OneAndMinusOne_Property(t *testing.T) {
	t.Parallel()

	one := num.Z().FromInt64(1)
	minusOne := num.Z().FromInt64(-1)

	invOne, err := one.TryInv()
	require.NoError(t, err)
	require.True(t, one.Mul(invOne).Equal(one))

	invMinusOne, err := minusOne.TryInv()
	require.NoError(t, err)
	require.True(t, minusOne.Mul(invMinusOne).Equal(one))
}
