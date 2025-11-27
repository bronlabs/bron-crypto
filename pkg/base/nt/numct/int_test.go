package numct_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func TestIntZero(t *testing.T) {
	t.Parallel()
	n := numct.IntZero()
	require.Equal(t, ct.True, n.IsZero())
	require.Equal(t, int64(0), n.Int64())
}

func TestIntOne(t *testing.T) {
	t.Parallel()
	n := numct.IntOne()
	require.Equal(t, ct.True, n.IsOne())
	require.Equal(t, int64(1), n.Int64())
}

func TestNewInt(t *testing.T) {
	t.Parallel()
	cases := []int64{0, 1, -1, 42, -42, 1000, -1000}
	for _, v := range cases {
		n := numct.NewInt(v)
		require.Equal(t, v, n.Int64())
	}
}

func TestNewIntFromUint64(t *testing.T) {
	t.Parallel()
	cases := []uint64{0, 1, 42, 1000, 0xFFFFFFFF}
	for _, v := range cases {
		n := numct.NewIntFromUint64(v)
		require.Equal(t, v, n.Uint64())
	}
}

func TestNewIntFromBytes(t *testing.T) {
	t.Parallel()
	// Sign-magnitude encoding: b[0] = sign, b[1:] = magnitude
	t.Run("positive", func(t *testing.T) {
		n := numct.NewIntFromBytes([]byte{0x00, 0x2A}) // +42
		require.Equal(t, int64(42), n.Int64())
	})

	t.Run("negative", func(t *testing.T) {
		n := numct.NewIntFromBytes([]byte{0x01, 0x2A}) // -42
		require.Equal(t, int64(-42), n.Int64())
	})

	t.Run("zero", func(t *testing.T) {
		n := numct.NewIntFromBytes([]byte{0x00, 0x00})
		require.Equal(t, int64(0), n.Int64())
	})
}

func TestNewIntFromBig(t *testing.T) {
	t.Parallel()
	cases := []int64{0, 1, -1, 42, -42, 1000, -1000}
	for _, v := range cases {
		b := big.NewInt(v)
		n := numct.NewIntFromBig(b, 64)
		require.Equal(t, v, n.Int64())
	}
}

func TestInt_Abs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input, expected int64
	}{
		{0, 0},
		{1, 1},
		{-1, 1},
		{42, 42},
		{-42, 42},
	}
	for _, tc := range cases {
		n := numct.NewInt(tc.input)
		n.Abs(n)
		require.Equal(t, tc.expected, n.Int64())
	}
}

func TestInt_Absed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input    int64
		expected uint64
	}{
		{0, 0},
		{1, 1},
		{-1, 1},
		{42, 42},
		{-42, 42},
	}
	for _, tc := range cases {
		n := numct.NewInt(tc.input)
		abs := n.Absed()
		require.Equal(t, tc.expected, abs.Uint64())
	}
}

func TestInt_Set(t *testing.T) {
	t.Parallel()
	a := numct.NewInt(-42)
	var b numct.Int
	b.Set(a)
	require.Equal(t, ct.True, b.Equal(a))
}

func TestInt_SetNat(t *testing.T) {
	t.Parallel()
	nat := numct.NewNat(42)
	var i numct.Int
	i.SetNat(nat)
	require.Equal(t, int64(42), i.Int64())
}

func TestInt_Clone(t *testing.T) {
	t.Parallel()
	a := numct.NewInt(-42)
	b := a.Clone()
	require.Equal(t, ct.True, a.Equal(b))

	// Verify it's a true copy
	b.Increment()
	require.Equal(t, ct.False, a.Equal(b))
}

func TestInt_SetZero(t *testing.T) {
	t.Parallel()
	n := numct.NewInt(42)
	n.SetZero()
	require.Equal(t, ct.True, n.IsZero())
}

func TestInt_SetOne(t *testing.T) {
	t.Parallel()
	n := numct.NewInt(42)
	n.SetOne()
	require.Equal(t, ct.True, n.IsOne())
}

func TestInt_Add(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected int64
	}{
		{0, 0, 0},
		{1, 2, 3},
		{-1, -2, -3},
		{5, -3, 2},
		{-5, 3, -2},
		{100, -100, 0},
	}
	for _, tc := range cases {
		var result numct.Int
		result.Add(numct.NewInt(tc.a), numct.NewInt(tc.b))
		require.Equal(t, tc.expected, result.Int64())
	}
}

func TestInt_AddCap(t *testing.T) {
	t.Parallel()
	var result numct.Int
	a := numct.NewInt(100)
	b := numct.NewInt(50)
	result.AddCap(a, b, 64)
	require.Equal(t, int64(150), result.Int64())
}

func TestInt_Neg(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input, expected int64
	}{
		{0, 0},
		{1, -1},
		{-1, 1},
		{42, -42},
		{-42, 42},
	}
	for _, tc := range cases {
		var result numct.Int
		result.Neg(numct.NewInt(tc.input))
		require.Equal(t, tc.expected, result.Int64())
	}
}

func TestInt_Sub(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected int64
	}{
		{0, 0, 0},
		{5, 3, 2},
		{3, 5, -2},
		{-5, -3, -2},
		{5, -3, 8},
		{-5, 3, -8},
	}
	for _, tc := range cases {
		var result numct.Int
		result.Sub(numct.NewInt(tc.a), numct.NewInt(tc.b))
		require.Equal(t, tc.expected, result.Int64())
	}
}

func TestInt_SubCap(t *testing.T) {
	t.Parallel()
	var result numct.Int
	a := numct.NewInt(100)
	b := numct.NewInt(30)
	result.SubCap(a, b, 64)
	require.Equal(t, int64(70), result.Int64())
}

func TestInt_Mul(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, expected int64
	}{
		{0, 5, 0},
		{1, 1, 1},
		{2, 3, 6},
		{-2, 3, -6},
		{-2, -3, 6},
		{10, -10, -100},
	}
	for _, tc := range cases {
		var result numct.Int
		result.Mul(numct.NewInt(tc.a), numct.NewInt(tc.b))
		require.Equal(t, tc.expected, result.Int64())
	}
}

func TestInt_MulCap(t *testing.T) {
	t.Parallel()
	var result numct.Int
	a := numct.NewInt(10)
	b := numct.NewInt(-5)
	result.MulCap(a, b, 64)
	require.Equal(t, int64(-50), result.Int64())
}

func TestInt_Div(t *testing.T) {
	t.Parallel()
	t.Run("positive/positive", func(t *testing.T) {
		var result numct.Int
		ok := result.Div(numct.NewInt(100), numct.NewInt(10))
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(10), result.Int64())
	})

	t.Run("negative/positive", func(t *testing.T) {
		var result numct.Int
		ok := result.Div(numct.NewInt(-100), numct.NewInt(10))
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(-10), result.Int64())
	})

	t.Run("positive/negative", func(t *testing.T) {
		var result numct.Int
		ok := result.Div(numct.NewInt(100), numct.NewInt(-10))
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(-10), result.Int64())
	})

	t.Run("negative/negative", func(t *testing.T) {
		var result numct.Int
		ok := result.Div(numct.NewInt(-100), numct.NewInt(-10))
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(10), result.Int64())
	})

	t.Run("integer division", func(t *testing.T) {
		var result numct.Int
		ok := result.Div(numct.NewInt(17), numct.NewInt(5))
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(3), result.Int64())
	})
}

func TestInt_ExactDiv(t *testing.T) {
	t.Parallel()
	t.Run("exact", func(t *testing.T) {
		var result numct.Int
		denom, ok := numct.NewModulus(numct.NewNat(10))
		require.Equal(t, ct.True, ok)
		ok = result.ExactDiv(numct.NewInt(-100), denom)
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(-10), result.Int64())
	})

	t.Run("not exact", func(t *testing.T) {
		var result numct.Int
		result.SetOne()
		denom, ok := numct.NewModulus(numct.NewNat(5))
		require.Equal(t, ct.True, ok)
		ok = result.ExactDiv(numct.NewInt(17), denom)
		require.Equal(t, ct.False, ok)
	})
}

func TestInt_IsUnit(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.True, numct.NewInt(1).IsUnit())
	require.Equal(t, ct.True, numct.NewInt(-1).IsUnit())
	require.Equal(t, ct.False, numct.NewInt(0).IsUnit())
	require.Equal(t, ct.False, numct.NewInt(2).IsUnit())
	require.Equal(t, ct.False, numct.NewInt(-2).IsUnit())
}

func TestInt_Inv(t *testing.T) {
	t.Parallel()
	t.Run("unit 1", func(t *testing.T) {
		var result numct.Int
		ok := result.Inv(numct.NewInt(1))
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(1), result.Int64())
	})

	t.Run("unit -1", func(t *testing.T) {
		var result numct.Int
		ok := result.Inv(numct.NewInt(-1))
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(-1), result.Int64())
	})

	t.Run("non-unit", func(t *testing.T) {
		var result numct.Int
		result.SetOne()
		ok := result.Inv(numct.NewInt(2))
		require.Equal(t, ct.False, ok)
	})
}

func TestInt_Double(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input, expected int64
	}{
		{0, 0},
		{1, 2},
		{-1, -2},
		{21, 42},
		{-21, -42},
	}
	for _, tc := range cases {
		var result numct.Int
		result.Double(numct.NewInt(tc.input))
		require.Equal(t, tc.expected, result.Int64())
	}
}

func TestInt_IsNegative(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.False, numct.NewInt(0).IsNegative())
	require.Equal(t, ct.False, numct.NewInt(1).IsNegative())
	require.Equal(t, ct.True, numct.NewInt(-1).IsNegative())
	require.Equal(t, ct.False, numct.NewInt(42).IsNegative())
	require.Equal(t, ct.True, numct.NewInt(-42).IsNegative())
}

func TestInt_IsZero(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.True, numct.NewInt(0).IsZero())
	require.Equal(t, ct.False, numct.NewInt(1).IsZero())
	require.Equal(t, ct.False, numct.NewInt(-1).IsZero())
}

func TestInt_IsNonZero(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.False, numct.NewInt(0).IsNonZero())
	require.Equal(t, ct.True, numct.NewInt(1).IsNonZero())
	require.Equal(t, ct.True, numct.NewInt(-1).IsNonZero())
}

func TestInt_IsOne(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.False, numct.NewInt(0).IsOne())
	require.Equal(t, ct.True, numct.NewInt(1).IsOne())
	require.Equal(t, ct.False, numct.NewInt(-1).IsOne())
	require.Equal(t, ct.False, numct.NewInt(2).IsOne())
}

func TestInt_Sqrt(t *testing.T) {
	t.Parallel()

	t.Run("small perfect squares (fast path)", func(t *testing.T) {
		cases := []struct {
			input    int64
			expected int64
			ok       bool
		}{
			{0, 0, true},
			{1, 1, true},
			{4, 2, true},
			{9, 3, true},
			{16, 4, true},
			{25, 5, true},
			{36, 6, true},
			{49, 7, true},
			{64, 8, true},
			{81, 9, true},
			{100, 10, true},
			{144, 12, true},
			{256, 16, true},
			{1000000, 1000, true},
			{2, 0, false},  // not a perfect square
			{3, 0, false},  // not a perfect square
			{-1, 0, false}, // negative
			{-4, 0, false}, // negative (even though |x| is perfect square)
			{-9, 0, false}, // negative
		}
		for _, tc := range cases {
			n := numct.NewInt(tc.input)
			original := n.Clone()
			var root numct.Int
			ok := root.Sqrt(n)
			if tc.ok {
				require.Equal(t, ct.True, ok, "input %d should be a perfect square", tc.input)
				require.Equal(t, tc.expected, root.Int64(), "sqrt(%d) should be %d", tc.input, tc.expected)
			} else {
				require.Equal(t, ct.False, ok, "input %d should not be a perfect square", tc.input)
				// When called on self, should leave unchanged on failure
				root.Set(original)
				ok = root.Sqrt(&root)
				require.Equal(t, ct.False, ok, "input %d should not be a perfect square", tc.input)
				require.Equal(t, ct.True, root.Equal(original), "should leave value unchanged on failure")
			}
		}
	})

	t.Run("large perfect squares (multi-limb path)", func(t *testing.T) {
		// Test numbers > 64 bits to exercise multi-limb path
		cases := []struct {
			name string
			root *big.Int
		}{
			{"2^64", new(big.Int).Lsh(big.NewInt(1), 64)},
			{"2^100", new(big.Int).Lsh(big.NewInt(1), 100)},
			{"2^128", new(big.Int).Lsh(big.NewInt(1), 128)},
			{"2^200", new(big.Int).Lsh(big.NewInt(1), 200)},
			{"large value", new(big.Int).SetBytes([]byte{
				0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			})},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				// Compute root^2
				squared := new(big.Int).Mul(tc.root, tc.root)
				n := numct.NewIntFromBig(squared, squared.BitLen())

				var root numct.Int
				ok := root.Sqrt(n)

				require.Equal(t, ct.True, ok, "should be a perfect square")
				require.Equal(t, 0, root.Big().Cmp(tc.root), "sqrt should equal original root")
			})
		}
	})

	t.Run("large non-perfect squares (multi-limb path)", func(t *testing.T) {
		// Numbers > 64 bits that are not perfect squares
		cases := []struct {
			name string
			n    *big.Int
		}{
			{"2^65 + 1", new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 65), big.NewInt(1))},
			{"2^100 + 7", new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(7))},
			{"2^128 - 1", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				n := numct.NewIntFromBig(tc.n, tc.n.BitLen())
				original := n.Clone()

				ok := n.Sqrt(n)

				require.Equal(t, ct.False, ok, "should not be a perfect square")
				require.Equal(t, ct.True, n.Equal(original), "should leave value unchanged")
			})
		}
	})

	t.Run("large negative numbers", func(t *testing.T) {
		// Large negative numbers should always fail
		largeNeg := new(big.Int).Lsh(big.NewInt(1), 128)
		largeNeg.Neg(largeNeg)
		n := numct.NewIntFromBig(largeNeg, largeNeg.BitLen())
		original := n.Clone()

		ok := n.Sqrt(n)

		require.Equal(t, ct.False, ok, "negative should not be a perfect square")
		require.Equal(t, ct.True, n.Equal(original), "should leave value unchanged")
	})

	t.Run("edge cases", func(t *testing.T) {
		// max uint64 squared
		maxU64 := new(big.Int).SetUint64(^uint64(0))
		maxSquared := new(big.Int).Mul(maxU64, maxU64)
		n := numct.NewIntFromBig(maxSquared, maxSquared.BitLen())

		var root numct.Int
		ok := root.Sqrt(n)

		require.Equal(t, ct.True, ok)
		require.Equal(t, 0, root.Big().Cmp(maxU64))
	})
}

func TestInt_Square(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input, expected int64
	}{
		{0, 0},
		{1, 1},
		{-1, 1},
		{5, 25},
		{-5, 25},
	}
	for _, tc := range cases {
		var result numct.Int
		result.Square(numct.NewInt(tc.input))
		require.Equal(t, tc.expected, result.Int64())
	}
}

func TestInt_Bit(t *testing.T) {
	t.Parallel()
	n := numct.NewInt(0b10101010) // 170
	require.Equal(t, byte(0), n.Bit(0))
	require.Equal(t, byte(1), n.Bit(1))
	require.Equal(t, byte(0), n.Bit(2))
	require.Equal(t, byte(1), n.Bit(3))
}

func TestInt_Bytes(t *testing.T) {
	t.Parallel()
	t.Run("positive", func(t *testing.T) {
		n := numct.NewInt(42)
		b := n.Bytes()
		require.Equal(t, byte(0), b[0]) // sign = 0 for positive
	})

	t.Run("negative", func(t *testing.T) {
		n := numct.NewInt(-42)
		b := n.Bytes()
		require.Equal(t, byte(1), b[0]) // sign = 1 for negative
	})
}

func TestInt_SetBytes(t *testing.T) {
	t.Parallel()
	t.Run("positive", func(t *testing.T) {
		var n numct.Int
		ok := n.SetBytes([]byte{0x00, 0x2A}) // +42
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(42), n.Int64())
	})

	t.Run("negative", func(t *testing.T) {
		var n numct.Int
		ok := n.SetBytes([]byte{0x01, 0x2A}) // -42
		require.Equal(t, ct.True, ok)
		require.Equal(t, int64(-42), n.Int64())
	})

	t.Run("empty", func(t *testing.T) {
		var n numct.Int
		ok := n.SetBytes([]byte{})
		require.Equal(t, ct.False, ok)
	})
}

func TestInt_Increment(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input, expected int64
	}{
		{0, 1},
		{1, 2},
		{-1, 0},
		{-2, -1},
	}
	for _, tc := range cases {
		n := numct.NewInt(tc.input)
		n.Increment()
		require.Equal(t, tc.expected, n.Int64())
	}
}

func TestInt_Decrement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input, expected int64
	}{
		{0, -1},
		{1, 0},
		{2, 1},
		{-1, -2},
	}
	for _, tc := range cases {
		n := numct.NewInt(tc.input)
		n.Decrement()
		require.Equal(t, tc.expected, n.Int64())
	}
}

func TestInt_Lsh(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value    int64
		shift    uint
		expected int64
	}{
		{1, 0, 1},
		{1, 1, 2},
		{1, 4, 16},
		{-1, 1, -2},
		{-1, 4, -16},
	}
	for _, tc := range cases {
		var result numct.Int
		result.Lsh(numct.NewInt(tc.value), tc.shift)
		require.Equal(t, tc.expected, result.Int64())
	}
}

func TestInt_Rsh(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value    int64
		shift    uint
		expected int64
	}{
		{1, 0, 1},
		{2, 1, 1},
		{16, 4, 1},
		{-2, 1, -1},
		{-16, 4, -1},
	}
	for _, tc := range cases {
		var result numct.Int
		result.Rsh(numct.NewInt(tc.value), tc.shift)
		require.Equal(t, tc.expected, result.Int64())
	}
}

func TestInt_Coprime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b     int64
		expected ct.Bool
	}{
		{15, 28, ct.True},
		{-15, 28, ct.True},
		{15, -28, ct.True},
		{-15, -28, ct.True},
		{12, 18, ct.False},
		{1, 100, ct.True},
	}
	for _, tc := range cases {
		result := numct.NewInt(tc.a).Coprime(numct.NewInt(tc.b))
		require.Equal(t, tc.expected, result)
	}
}

func TestInt_IsProbablyPrime(t *testing.T) {
	t.Parallel()
	primes := []int64{2, 3, 5, 7, 11, 13, 17, 19, 23}
	for _, p := range primes {
		require.Equal(t, ct.True, numct.NewInt(p).IsProbablyPrime())
	}

	composites := []int64{4, 6, 8, 9, 10, 12}
	for _, c := range composites {
		require.Equal(t, ct.False, numct.NewInt(c).IsProbablyPrime())
	}

	// Negative numbers are not prime
	require.Equal(t, ct.False, numct.NewInt(-7).IsProbablyPrime())
}

func TestInt_Select(t *testing.T) {
	t.Parallel()
	x0 := numct.NewInt(10)
	x1 := numct.NewInt(-20)

	t.Run("choice 0", func(t *testing.T) {
		var result numct.Int
		result.Select(0, x0, x1)
		require.Equal(t, ct.True, result.Equal(x0))
	})

	t.Run("choice 1", func(t *testing.T) {
		var result numct.Int
		result.Select(1, x0, x1)
		require.Equal(t, ct.True, result.Equal(x1))
	})
}

func TestInt_CondAssign(t *testing.T) {
	t.Parallel()
	t.Run("choice 0 keeps original", func(t *testing.T) {
		n := numct.NewInt(10)
		x := numct.NewInt(-20)
		n.CondAssign(0, x)
		require.Equal(t, int64(10), n.Int64())
	})

	t.Run("choice 1 assigns", func(t *testing.T) {
		n := numct.NewInt(10)
		x := numct.NewInt(-20)
		n.CondAssign(1, x)
		require.Equal(t, int64(-20), n.Int64())
	})
}

func TestInt_CondNeg(t *testing.T) {
	t.Parallel()
	t.Run("choice 0 keeps sign", func(t *testing.T) {
		n := numct.NewInt(42)
		n.CondNeg(0)
		require.Equal(t, int64(42), n.Int64())
	})

	t.Run("choice 1 negates", func(t *testing.T) {
		n := numct.NewInt(42)
		n.CondNeg(1)
		require.Equal(t, int64(-42), n.Int64())
	})
}

func TestInt_Equal(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.True, numct.NewInt(42).Equal(numct.NewInt(42)))
	require.Equal(t, ct.True, numct.NewInt(-42).Equal(numct.NewInt(-42)))
	require.Equal(t, ct.False, numct.NewInt(42).Equal(numct.NewInt(-42)))
	require.Equal(t, ct.False, numct.NewInt(42).Equal(numct.NewInt(43)))
}

func TestInt_Compare(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b       int64
		lt, eq, gt ct.Bool
	}{
		{5, 10, ct.True, ct.False, ct.False},
		{10, 10, ct.False, ct.True, ct.False},
		{10, 5, ct.False, ct.False, ct.True},
		{-5, 5, ct.True, ct.False, ct.False},
		{5, -5, ct.False, ct.False, ct.True},
		{-10, -5, ct.True, ct.False, ct.False},
		{-5, -10, ct.False, ct.False, ct.True},
		{-5, -5, ct.False, ct.True, ct.False},
	}
	for _, tc := range cases {
		lt, eq, gt := numct.NewInt(tc.a).Compare(numct.NewInt(tc.b))
		require.Equal(t, tc.lt, lt, "a=%d, b=%d", tc.a, tc.b)
		require.Equal(t, tc.eq, eq, "a=%d, b=%d", tc.a, tc.b)
		require.Equal(t, tc.gt, gt, "a=%d, b=%d", tc.a, tc.b)
	}
}

func TestInt_Uint64(t *testing.T) {
	t.Parallel()
	// Uint64 returns absolute value
	require.Equal(t, uint64(42), numct.NewInt(42).Uint64())
	require.Equal(t, uint64(42), numct.NewInt(-42).Uint64())
}

func TestInt_SetUint64(t *testing.T) {
	t.Parallel()
	var n numct.Int
	n.SetUint64(42)
	require.Equal(t, uint64(42), n.Uint64())
	require.Equal(t, ct.False, n.IsNegative())
}

func TestInt_Int64(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(42), numct.NewInt(42).Int64())
	require.Equal(t, int64(-42), numct.NewInt(-42).Int64())
	require.Equal(t, int64(0), numct.NewInt(0).Int64())
}

func TestInt_SetInt64(t *testing.T) {
	t.Parallel()
	cases := []int64{0, 1, -1, 42, -42, 1000, -1000}
	for _, v := range cases {
		var n numct.Int
		n.SetInt64(v)
		require.Equal(t, v, n.Int64())
	}
}

func TestInt_TrueLen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value    int64
		expected int
	}{
		{0, 0},
		{1, 1},
		{-1, 1},
		{255, 8},
		{-255, 8},
	}
	for _, tc := range cases {
		n := numct.NewInt(tc.value)
		require.Equal(t, tc.expected, n.TrueLen())
	}
}

func TestInt_AnnouncedLen(t *testing.T) {
	t.Parallel()
	n := numct.NewInt(42)
	// NewInt uses SetInt64 which sets announced len to 64 (to accommodate MinInt64)
	require.Equal(t, 64, n.AnnouncedLen())
}

func TestInt_IsOdd(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.False, numct.NewInt(0).IsOdd())
	require.Equal(t, ct.True, numct.NewInt(1).IsOdd())
	require.Equal(t, ct.True, numct.NewInt(-1).IsOdd())
	require.Equal(t, ct.False, numct.NewInt(2).IsOdd())
	require.Equal(t, ct.False, numct.NewInt(-2).IsOdd())
}

func TestInt_IsEven(t *testing.T) {
	t.Parallel()
	require.Equal(t, ct.True, numct.NewInt(0).IsEven())
	require.Equal(t, ct.False, numct.NewInt(1).IsEven())
	require.Equal(t, ct.False, numct.NewInt(-1).IsEven())
	require.Equal(t, ct.True, numct.NewInt(2).IsEven())
	require.Equal(t, ct.True, numct.NewInt(-2).IsEven())
}

func TestInt_String(t *testing.T) {
	t.Parallel()
	n := numct.NewInt(255)
	s := n.String()
	require.Contains(t, s, "FF")
}

func TestInt_HashCode(t *testing.T) {
	t.Parallel()
	a := numct.NewInt(42)
	b := numct.NewInt(42)
	c := numct.NewInt(-42)

	require.Equal(t, a.HashCode(), b.HashCode())
	require.NotEqual(t, a.HashCode(), c.HashCode())
}

func TestInt_Big(t *testing.T) {
	t.Parallel()
	cases := []int64{0, 1, -1, 42, -42}
	for _, v := range cases {
		n := numct.NewInt(v)
		b := n.Big()
		require.Equal(t, v, b.Int64())
	}
}

func TestInt_Not(t *testing.T) {
	t.Parallel()
	// ~x = -(x+1) in two's complement
	cases := []struct {
		input, expected int64
	}{
		{0, -1},
		{1, -2},
		{-1, 0},
		{-2, 1},
		{7, -8},
	}
	for _, tc := range cases {
		var result numct.Int
		result.Not(numct.NewInt(tc.input))
		require.Equal(t, tc.expected, result.Int64())
	}
}

func TestInt_SetRandomRangeLH(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	low := numct.NewInt(-50)
	high := numct.NewInt(50)

	var n numct.Int
	err := n.SetRandomRangeLH(low, high, prng)
	require.NoError(t, err)

	// Check n is in range [-50, 50)
	lt, _, _ := n.Compare(low)
	require.Equal(t, ct.False, lt) // n >= low

	lt, _, _ = n.Compare(high)
	require.Equal(t, ct.True, lt) // n < high
}

func TestInt_SetRandomRangeLH_Errors(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	t.Run("low equals high", func(t *testing.T) {
		var n numct.Int
		err := n.SetRandomRangeLH(numct.NewInt(10), numct.NewInt(10), prng)
		require.Error(t, err)
	})
}

func TestInt_Resize(t *testing.T) {
	t.Parallel()
	n := numct.NewInt(-42)
	originalLen := n.AnnouncedLen()
	n.Resize(128)
	require.NotEqual(t, originalLen, n.AnnouncedLen())
	require.Equal(t, int64(-42), n.Int64())
}

func TestInt_LshCap(t *testing.T) {
	t.Parallel()
	var result numct.Int
	n := numct.NewInt(0x0F)
	result.LshCap(n, 4, -1)
	require.Equal(t, int64(0xF0), result.Int64())
}

func TestInt_RshCap(t *testing.T) {
	t.Parallel()
	var result numct.Int
	n := numct.NewInt(0xF0)
	result.RshCap(n, 4, -1)
	require.Equal(t, int64(0x0F), result.Int64())
}

func TestInt_Bytes_RoundTrip(t *testing.T) {
	t.Parallel()
	cases := []int64{0, 1, -1, 42, -42, 1000, -1000}
	for _, v := range cases {
		original := numct.NewInt(v)
		encoded := original.Bytes()

		var decoded numct.Int
		ok := decoded.SetBytes(encoded)
		require.Equal(t, ct.True, ok)
		require.Equal(t, v, decoded.Int64())
	}
}

func TestInt_DivCap(t *testing.T) {
	t.Parallel()
	var result numct.Int
	num := numct.NewInt(-100)
	denom, ok := numct.NewModulus(numct.NewNat(10))
	require.Equal(t, ct.True, ok)

	ok = result.DivCap(num, denom, -1)
	require.Equal(t, ct.True, ok)
	require.Equal(t, int64(-10), result.Int64())
}

func TestInt_FillBytes_Equivalence(t *testing.T) {
	t.Parallel()
	// Verify that Bytes produces sign-magnitude encoding
	n := numct.NewInt(-42)
	b := n.Bytes()

	// First byte is sign
	require.Equal(t, byte(1), b[0])

	// Remaining bytes are magnitude (big-endian)
	mag := numct.NewNat(42).Bytes()
	require.True(t, bytes.Equal(b[1:], mag))
}
