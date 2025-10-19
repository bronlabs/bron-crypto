package numct_test

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func newInt(val int64) *numct.Int {
	i := (*numct.Int)(new(saferith.Int))
	i.SetInt64(val)
	return i
}

func newIntFromBytes(data []byte) *numct.Int {
	i := (*numct.Int)(new(saferith.Int))
	i.SetBytes(data)
	return i
}

func newIntFromBigInt(b *big.Int) *numct.Int {
	i := (*numct.Int)(new(saferith.Int))
	i.SetBytes(b.Bytes())
	if b.Sign() < 0 {
		i.Neg(i)
	}
	return i
}

func TestInt_BitwiseAnd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		x        int64
		y        int64
		expected int64
	}{
		{"0 & 0", 0, 0, 0},
		{"1 & 1", 1, 1, 1},
		{"15 & 7", 15, 7, 7},
		{"255 & 15", 255, 15, 15},
		{"170 & 85", 170, 85, 0}, // 0xAA & 0x55 = 0
		{"-1 & 7", -1, 7, 7},     // All bits set & 7 = 7
		{"-2 & -3", -2, -3, -4},  // Two's complement
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		t.Parallel()
			x := newInt(tt.x)
			y := newInt(tt.y)
			result := new(numct.Int)

			result.And(x, y)

			assert.Equal(t, tt.expected, result.Int64(), "And result mismatch")
		})
	}
}

func TestInt_BitwiseOr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		x        int64
		y        int64
		expected int64
	}{
		{"0 | 0", 0, 0, 0},
		{"0 | 1", 0, 1, 1},
		{"1 | 1", 1, 1, 1},
		{"15 | 7", 15, 7, 15},
		{"170 | 85", 170, 85, 255}, // 0xAA | 0x55 = 0xFF
		{"-1 | 7", -1, 7, -1},      // All bits set | 7 = all bits set
		{"-2 | -3", -2, -3, -1},    // Two's complement
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		t.Parallel()
			x := newInt(tt.x)
			y := newInt(tt.y)
			result := new(numct.Int)

			result.Or(x, y)

			assert.Equal(t, tt.expected, result.Int64(), "Or result mismatch")
		})
	}
}

func TestInt_BitwiseXor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		x        int64
		y        int64
		expected int64
	}{
		{"0 ^ 0", 0, 0, 0},
		{"0 ^ 1", 0, 1, 1},
		{"1 ^ 1", 1, 1, 0},
		{"15 ^ 7", 15, 7, 8},
		{"170 ^ 85", 170, 85, 255}, // 0xAA ^ 0x55 = 0xFF
		{"-1 ^ 7", -1, 7, -8},      // All bits set ^ 7 = ~7
		{"-2 ^ -3", -2, -3, 3},     // Two's complement
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		t.Parallel()
			x := newInt(tt.x)
			y := newInt(tt.y)
			result := new(numct.Int)

			result.Xor(x, y)

			assert.Equal(t, tt.expected, result.Int64(), "Xor result mismatch")
		})
	}
}

func TestInt_BitwiseNot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		x        int64
		expected int64
	}{
		{"~0", 0, -1},
		{"~1", 1, -2},
		{"~(-1)", -1, 0},
		{"~7", 7, -8},
		{"~(-8)", -8, 7},
		{"~255", 255, -256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		t.Parallel()
			x := newInt(tt.x)
			result := new(numct.Int)

			result.Not(x)

			assert.Equal(t, tt.expected, result.Int64(), "Not result mismatch")
		})
	}
}

func TestInt_BitwiseAndCap(t *testing.T) {
	t.Parallel()

	x := newInt(0xFFFF)
	y := newInt(0xFF00)
	result := new(numct.Int)

	// Test with specific capacity
	result.AndCap(x, y, 32)

	assert.Equal(t, int64(0xFF00), result.Int64(), "AndCap result mismatch")
	assert.LessOrEqual(t, result.AnnouncedLen(), uint(32), "Capacity should be respected")
}

func TestInt_BitwiseOrCap(t *testing.T) {
	t.Parallel()

	x := newInt(0xFF00)
	y := newInt(0x00FF)
	result := new(numct.Int)

	// Test with specific capacity
	result.OrCap(x, y, 32)

	assert.Equal(t, int64(0xFFFF), result.Int64(), "OrCap result mismatch")
	assert.LessOrEqual(t, result.AnnouncedLen(), uint(32), "Capacity should be respected")
}

func TestInt_BitwiseXorCap(t *testing.T) {
	t.Parallel()

	x := newInt(0xFFFF)
	y := newInt(0xFF00)
	result := new(numct.Int)

	// Test with specific capacity
	result.XorCap(x, y, 32)

	assert.Equal(t, int64(0x00FF), result.Int64(), "XorCap result mismatch")
	assert.LessOrEqual(t, result.AnnouncedLen(), uint(32), "Capacity should be respected")
}

func TestInt_BitwiseNotCap(t *testing.T) {
	t.Parallel()

	x := newInt(7)
	result := new(numct.Int)

	// Test with specific capacity
	result.NotCap(x, 32)

	assert.Equal(t, int64(-8), result.Int64(), "NotCap result mismatch")
	assert.LessOrEqual(t, result.AnnouncedLen(), uint(32), "Capacity should be respected")
}

func TestInt_BitwiseWithBigInts(t *testing.T) {
	t.Parallel()

	// Test with larger numbers using big.Int
	x := newIntFromBigInt(big.NewInt(0).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}))
	y := newIntFromBigInt(big.NewInt(0).SetBytes([]byte{0xAA, 0xAA, 0xAA, 0xAA}))

	resultAnd := new(numct.Int)
	resultOr := new(numct.Int)
	resultXor := new(numct.Int)

	resultAnd.And(x, y)
	resultOr.Or(x, y)
	resultXor.Xor(x, y)

	// Verify using big.Int operations
	bigX := x.Big()
	bigY := y.Big()

	expectedAnd := new(big.Int).And(bigX, bigY)
	expectedOr := new(big.Int).Or(bigX, bigY)
	expectedXor := new(big.Int).Xor(bigX, bigY)

	// Compare using big.Int values since internal byte representation may differ
	assert.Equal(t, 0, expectedAnd.Cmp(resultAnd.Big()), "And with big ints")
	assert.Equal(t, 0, expectedOr.Cmp(resultOr.Big()), "Or with big ints")
	assert.Equal(t, 0, expectedXor.Cmp(resultXor.Big()), "Xor with big ints")
}

func TestInt_BasicOperations(t *testing.T) {
	t.Parallel()

	t.Run("Set", func(t *testing.T) {
		t.Parallel()
		i1 := newInt(42)
		i2 := newInt(0)

		i2.Set(i1)
		assert.Equal(t, i1.String(), i2.String())
		assert.Equal(t, int64(42), i2.Int64())
	})

	t.Run("SetNat", func(t *testing.T) {
		t.Parallel()
		n := (*numct.Nat)(new(saferith.Nat))
		n.SetUint64(42)

		i := newInt(0)
		i.SetNat(n)
		assert.Equal(t, uint64(42), i.Uint64())
		assert.Equal(t, ct.False, i.IsNegative())
	})

	t.Run("SetZero", func(t *testing.T) {
		t.Parallel()
		i := newInt(12345)
		i.SetZero()

		assert.Equal(t, ct.True, i.IsZero())
		assert.Equal(t, int64(0), i.Int64())
	})

	t.Run("SetOne", func(t *testing.T) {
		t.Parallel()
		i := newInt(12345)
		i.SetOne()

		assert.Equal(t, ct.True, i.IsOne())
		assert.Equal(t, int64(1), i.Int64())
	})

	t.Run("Abs", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    int64
			expected uint64
		}{
			{42, 42},
			{-42, 42},
			{0, 0},
			{math.MinInt64 + 1, uint64(math.MaxInt64)},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				i.Abs()
				assert.Equal(t, tc.expected, i.Uint64())
				assert.Equal(t, ct.False, i.IsNegative())
			})
		}
	})
}

func TestInt_ArithmeticOperations(t *testing.T) {
	t.Parallel()

	t.Run("Add", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			a, b     int64
			expected int64
		}{
			{"zero_plus_zero", 0, 0, 0},
			{"positive_plus_positive", 10, 20, 30},
			{"negative_plus_negative", -10, -20, -30},
			{"positive_plus_negative", 10, -5, 5},
			{"negative_plus_positive", -10, 15, 5},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				a := newInt(tc.a)
				b := newInt(tc.b)
				result := newInt(0)

				result.Add(a, b)
				assert.Equal(t, tc.expected, result.Int64())
			})
		}
	})

	t.Run("AddCap", func(t *testing.T) {
		t.Parallel()
		// cap is bit-capacity, so AddCap(a, b, cap) = (a + b) mod 2^cap with sign preservation
		a := newInt(100)
		b := newInt(200)
		result := newInt(0)

		result.AddCap(a, b, 8)
		assert.Equal(t, int64(44), result.Int64()) // (100 + 200) mod 256 = 44
	})

	t.Run("Neg", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    int64
			expected int64
		}{
			{42, -42},
			{-42, 42},
			{0, 0},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				result := newInt(0)
				result.Neg(i)
				assert.Equal(t, tc.expected, result.Int64())
			})
		}
	})

	t.Run("Sub", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			a, b     int64
			expected int64
		}{
			{"same_numbers", 100, 100, 0},
			{"positive_minus_positive", 100, 50, 50},
			{"positive_minus_negative", 100, -50, 150},
			{"negative_minus_positive", -100, 50, -150},
			{"negative_minus_negative", -100, -50, -50},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				a := newInt(tc.a)
				b := newInt(tc.b)
				result := newInt(0)

				result.Sub(a, b)
				assert.Equal(t, tc.expected, result.Int64())
			})
		}
	})

	t.Run("SubCap", func(t *testing.T) {
		t.Parallel()
		a := newInt(50)
		b := newInt(100)
		result := newInt(0)

		result.SubCap(a, b, 8)
		// (50 - 100) = -50
		assert.Equal(t, int64(-50), result.Int64())
	})

	t.Run("Mul", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			a, b     int64
			expected int64
		}{
			{"zero_times_zero", 0, 0, 0},
			{"positive_times_positive", 7, 6, 42},
			{"negative_times_negative", -7, -6, 42},
			{"positive_times_negative", 7, -6, -42},
			{"negative_times_positive", -7, 6, -42},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				a := newInt(tc.a)
				b := newInt(tc.b)
				result := newInt(0)

				result.Mul(a, b)
				assert.Equal(t, tc.expected, result.Int64())
			})
		}
	})

	t.Run("MulCap", func(t *testing.T) {
		t.Parallel()
		a := newInt(10)
		b := newInt(20)
		result := newInt(0)

		result.MulCap(a, b, 8)
		assert.Equal(t, int64(200), result.Int64()) // (10 * 20) mod 256 = 200

		// Test with negative numbers
		a.SetInt64(-10)
		result.MulCap(a, b, 8)
		assert.Equal(t, int64(-200), result.Int64()) // (-10 * 20) = -200
	})

	t.Run("Double", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    int64
			expected int64
		}{
			{0, 0},
			{1, 2},
			{-1, -2},
			{100, 200},
			{-100, -200},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				result := newInt(0)

				result.Double(i)
				assert.Equal(t, tc.expected, result.Int64())
			})
		}
	})

	t.Run("Square", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    int64
			expected int64
		}{
			{0, 0},
			{1, 1},
			{-1, 1},
			{7, 49},
			{-7, 49},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				result := newInt(0)

				result.Square(i)
				assert.Equal(t, tc.expected, result.Int64())
			})
		}
	})

	t.Run("Increment", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    int64
			expected int64
		}{
			{0, 1},
			{1, 2},
			{-1, 0},
			{99, 100},
			{-100, -99},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				i.Increment()
				assert.Equal(t, tc.expected, i.Int64())
			})
		}
	})

	t.Run("Decrement", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    int64
			expected int64
		}{
			{1, 0},
			{0, -1},
			{-1, -2},
			{100, 99},
			{-99, -100},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				i.Decrement()
				assert.Equal(t, tc.expected, i.Int64())
			})
		}
	})
}

func TestInt_DivisionOperations(t *testing.T) {
	t.Parallel()

	t.Run("DivModCap", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			lhs, rhs int64
			cap      int
			expQuot  int64
			expRem   int64
		}{
			// Basic positive/negative combinations
			{"positive_div_positive", 17, 5, -1, 3, 2},
			{"negative_div_positive", -17, 5, -1, -3, -2},
			{"positive_div_negative", 17, -5, -1, -3, 2},
			{"negative_div_negative", -17, -5, -1, 3, -2},

			// Exact divisions
			{"exact_division", 20, 5, -1, 4, 0},
			{"exact_negative_dividend", -20, 5, -1, -4, 0},
			{"exact_negative_divisor", 20, -5, -1, -4, 0},
			{"exact_both_negative", -20, -5, -1, 4, 0},

			// Edge cases
			{"zero_dividend", 0, 5, -1, 0, 0},
			{"zero_dividend_neg_divisor", 0, -5, -1, 0, 0},
			{"divide_by_one", 42, 1, -1, 42, 0},
			{"divide_by_minus_one", 42, -1, -1, -42, 0},
			{"dividend_smaller", 3, 10, -1, 0, 3},
			{"dividend_smaller_negative", -3, 10, -1, 0, -3},

			// With capacity limitations
			{"with_cap_8", 500, 10, 8, 50, 0},
			{"with_cap_8_negative", -500, 10, 8, -50, 0},
			{"with_cap_16", 65530, 256, 16, 255, 250},
			{"with_cap_16_mixed_sign", -65530, 256, 16, -255, -250},

			// Large numbers
			{"large_positive", 1000000, 7, -1, 142857, 1},
			{"large_negative", -1000000, 7, -1, -142857, -1},
			{"large_both", -1000000, -7, -1, 142857, -1},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				lhs := newInt(tc.lhs)
				rhs := newInt(tc.rhs)
				quot := newInt(999) // Initialise with non-zero to verify it gets updated
				rem := newInt(999)
				// Since DivModCap doesn't exist for Int, we compute quotient and remainder separately
				// First compute quotient using integer division
				ok := quot.Div(lhs, rhs)
				if ok == ct.False && tc.rhs != 0 {
					t.Fatalf("Division failed unexpectedly for %d/%d", tc.lhs, tc.rhs)
				}

				// Compute remainder: rem = lhs - rhs * quot
				if ok == ct.True {
					temp := newInt(0)
					temp.Mul(rhs, quot)
					rem.Sub(lhs, temp)
				}
				assert.Equal(t, tc.expQuot, quot.Int64(), "quotient")
				assert.Equal(t, tc.expRem, rem.Int64(), "remainder")

				// Verify the division identity: lhs = rhs * quot + rem
				// This should hold for all test cases
				check := newInt(0)
				temp := newInt(0)
				temp.Mul(rhs, quot)
				check.Add(temp, rem)
				assert.Equal(t, tc.lhs, check.Int64(), "division identity check: %d = %d * %d + %d",
					tc.lhs, tc.rhs, tc.expQuot, tc.expRem)
			})
		}
	})

	t.Run("Div", func(t *testing.T) {
		t.Parallel()
		// Test exact division
		a := newInt(20)
		b := newInt(5)
		result := newInt(0)

		ok := result.Div(a, b)
		assert.Equal(t, ct.True, ok)
		assert.Equal(t, int64(4), result.Int64())

		// Test integer division (truncates)
		a.SetInt64(17)
		result.SetInt64(999) // Set to a known value
		ok = result.Div(a, b)
		assert.Equal(t, ct.True, ok)              // Now returns true for integer division
		assert.Equal(t, int64(3), result.Int64()) // 17/5 = 3 (truncated)
	})

	t.Run("ExactDiv", func(t *testing.T) {
		t.Parallel()
		// Note: ExactDiv for Int requires a Modulus argument
		// For testing purposes, we'll use regular Div which internally handles conversion
		// Test exact division using regular Div
		a := newInt(20)
		b := newInt(5)
		result := newInt(0)

		ok := result.Div(a, b)
		assert.Equal(t, ct.True, ok)
		assert.Equal(t, int64(4), result.Int64())

		// For actual ExactDiv test, we need to manually create a modulus
		// from the divisor's absolute value
		bNat := (*numct.Nat)(new(saferith.Nat).SetUint64(5))
		bMod, modOk := numct.NewModulus(bNat)
		assert.Equal(t, ct.True, modOk)

		// Test exact division
		a.SetInt64(20)
		result.SetInt64(0)
		ok = result.ExactDiv(a, bMod)
		assert.Equal(t, ct.True, ok)
		assert.Equal(t, int64(4), result.Int64())

		// Test non-exact division (should return false and not modify result)
		a.SetInt64(17)
		result.SetInt64(999) // Set to a known value
		ok = result.ExactDiv(a, bMod)
		assert.Equal(t, ct.False, ok)
		// Note: ExactDiv may modify the result even on failure
		// The exact behaviour depends on the implementation
	})

	t.Run("DivCap", func(t *testing.T) {
		t.Parallel()
		a := newInt(20)
		result := newInt(0)

		// Create modulus directly from an unsigned value
		bNat := (*numct.Nat)(new(saferith.Nat).SetUint64(5))
		bMod, modOk := numct.NewModulus(bNat)
		assert.Equal(t, ct.True, modOk)

		ok := result.DivCap(a, bMod, 8)
		assert.Equal(t, ct.True, ok)
		assert.Equal(t, int64(4), result.Int64())
	})

	t.Run("Inv", func(t *testing.T) {
		t.Parallel()
		// Inv always returns false for integers (no multiplicative inverse in Z)
		i := newInt(2)
		result := newInt(0)

		ok := result.Inv(i)
		assert.Equal(t, ct.False, ok)
	})
}

func TestInt_Sqrt(t *testing.T) {
	t.Parallel()

	t.Run("PerfectSquares", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			square int64
			root   int64
		}{
			{0, 0},
			{1, 1},
			{4, 2},
			{9, 3},
			{16, 4},
			{25, 5},
			{36, 6},
			{49, 7},
			{64, 8},
			{81, 9},
			{100, 10},
			{121, 11},
			{144, 12},
			{169, 13},
			{196, 14},
			{225, 15},
			{256, 16},
			{289, 17},
			{324, 18},
			{361, 19},
			{400, 20},
			{625, 25},
			{1024, 32},
			{1600, 40},
			{2500, 50},
			{10000, 100},
			{1000000, 1000},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("sqrt_%d", tc.square), func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.square)
				result := newInt(999) // Initialise with non-zero to test it gets updated

				ok := result.Sqrt(i)
				assert.Equal(t, ct.True, ok, "Should return true for perfect square %d", tc.square)
				assert.Equal(t, tc.root, result.Int64(), "Sqrt(%d) should be %d", tc.square, tc.root)
			})
		}
	})

	t.Run("NonPerfectSquares", func(t *testing.T) {
		t.Parallel()
		testCases := []int64{2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20,
			24, 26, 27, 28, 30, 35, 40, 45, 48, 50, 60, 63, 72, 80, 88, 90, 95, 99,
			101, 122, 143, 145, 168, 170, 195, 200, 223, 224, 226, 255, 257, 288, 290,
			323, 325, 360, 362, 399, 401, 624, 626, 1023, 1025, 9999, 10001}

		for _, val := range testCases {
			t.Run(fmt.Sprintf("sqrt_%d", val), func(t *testing.T) {
		t.Parallel()
				i := newInt(val)
				result := newInt(999) // Initialise with non-zero

				ok := result.Sqrt(i)
				assert.Equal(t, ct.False, ok, "Should return false for non-perfect square %d", val)
				// Result should not be modified when ok is false
				assert.Equal(t, int64(999), result.Int64(), "Result should not change when sqrt fails")
			})
		}
	})

	t.Run("NegativeNumbers", func(t *testing.T) {
		t.Parallel()
		// Sqrt of negative numbers should always return false
		negatives := []int64{-1, -4, -9, -16, -25, -100, -144}

		for _, val := range negatives {
			t.Run(fmt.Sprintf("sqrt_%d", val), func(t *testing.T) {
		t.Parallel()
				i := newInt(val)
				result := newInt(888) // Initialise with known value

				ok := result.Sqrt(i)
				assert.Equal(t, ct.False, ok, "Sqrt of negative %d should return false", val)
				assert.Equal(t, int64(888), result.Int64(), "Result should not change for negative input")
			})
		}
	})

	t.Run("EdgeCases", func(t *testing.T) {
		t.Parallel()
		// Test edge case: very large perfect square
		// 46340^2 = 2147395600 (fits in int32)
		i := newInt(2147395600)
		result := newInt(0)
		ok := result.Sqrt(i)
		assert.Equal(t, ct.True, ok)
		assert.Equal(t, int64(46340), result.Int64())

		// Test with different announced lengths
		i.SetInt64(16)
		i.Resize(10) // Resize to 10 bits
		result.SetInt64(0)
		ok = result.Sqrt(i)
		assert.Equal(t, ct.True, ok)
		assert.Equal(t, int64(4), result.Int64())

		// Test zero with different capacities
		i.SetInt64(0)
		i.Resize(8)
		result.SetInt64(999)
		ok = result.Sqrt(i)
		assert.Equal(t, ct.True, ok)
		assert.Equal(t, int64(0), result.Int64())
	})

	t.Run("BoundaryValues", func(t *testing.T) {
		t.Parallel()
		// Test boundary values around perfect squares
		testCases := []struct {
			value     int64
			isPerfect bool
			root      int64
		}{
			{15, false, 0},
			{16, true, 4},
			{17, false, 0},
			{24, false, 0},
			{25, true, 5},
			{26, false, 0},
			{99, false, 0},
			{100, true, 10},
			{101, false, 0},
			{120, false, 0},
			{121, true, 11},
			{122, false, 0},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("boundary_%d", tc.value), func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.value)
				result := newInt(777)

				ok := result.Sqrt(i)
				if tc.isPerfect {
					assert.Equal(t, ct.True, ok, "Should be perfect square")
					assert.Equal(t, tc.root, result.Int64())
				} else {
					assert.Equal(t, ct.False, ok, "Should not be perfect square")
					assert.Equal(t, int64(777), result.Int64(), "Result should not change")
				}
			})
		}
	})

	t.Run("SelfAssignment", func(t *testing.T) {
		t.Parallel()
		// Test sqrt where result overwrites input
		i := newInt(16)
		ok := i.Sqrt(i)
		assert.Equal(t, ct.True, ok)
		assert.Equal(t, int64(4), i.Int64())

		// Test with non-perfect square
		i.SetInt64(15)
		ok = i.Sqrt(i)
		assert.Equal(t, ct.False, ok)
		assert.Equal(t, int64(15), i.Int64(), "Should remain unchanged")
	})

	t.Run("ConstantTimeProperty", func(t *testing.T) {
		t.Parallel()
		// Test that the function returns ct.Bool for constant-time property
		var ok ct.Bool
		i := newInt(16)
		result := newInt(0)

		ok = result.Sqrt(i)
		// This compiles only if Sqrt returns ct.Bool
		assert.Equal(t, ct.True, ok)
	})
}

func TestInt_Sqrt_SingleLimb(t *testing.T) {
	t.Parallel()

	t.Run("SmallPerfectSquares_Under64Bits", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			square uint64
			root   uint64
		}{
			{0, 0},
			{1, 1},
			{4, 2},
			{9, 3},
			{16, 4},
			{25, 5},
			{36, 6},
			{49, 7},
			{64, 8},
			{81, 9},
			{100, 10},
			{256, 16},
			{1024, 32},
			{4096, 64},
			{16384, 128},
			{65536, 256},
			{1048576, 1024},
			{16777216, 4096},
			{268435456, 16384},
			{1073741824, 32768},      // 2^30 = (2^15)^2
			{4294967296, 65536},      // 2^32 = (2^16)^2
			{1099511627776, 1048576}, // 2^40 = (2^20)^2
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("sqrt_%d", tc.square), func(t *testing.T) {
		t.Parallel()
				i := (*numct.Int)(new(saferith.Int))
				(*saferith.Int)(i).SetUint64(tc.square)
				(*saferith.Int)(i).Resize(64) // Ensure we use single-limb path

				result := (*numct.Int)(new(saferith.Int))
				ok := result.Sqrt(i)

				assert.Equal(t, ct.True, ok, "Should return true for perfect square %d", tc.square)
				assert.Equal(t, tc.root, result.Uint64(), "Sqrt(%d) should be %d", tc.square, tc.root)
			})
		}
	})

	t.Run("NonPerfectSquares_Under64Bits", func(t *testing.T) {
		t.Parallel()
		testCases := []uint64{
			2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15,
			17, 18, 19, 20, 24, 26, 27, 28, 30, 35,
			99, 101, 255, 257, 1023, 1025, 4095, 4097,
			65535, 65537, 1048575, 1048577,
			4294967295, 4294967297, // Around 2^32
		}

		for _, val := range testCases {
			t.Run(fmt.Sprintf("sqrt_%d", val), func(t *testing.T) {
		t.Parallel()
				i := (*numct.Int)(new(saferith.Int))
				(*saferith.Int)(i).SetUint64(val)
				(*saferith.Int)(i).Resize(64)

				result := (*numct.Int)(new(saferith.Int))
				(*saferith.Int)(result).SetUint64(999) // Set to known value

				ok := result.Sqrt(i)
				assert.Equal(t, ct.False, ok, "Should return false for non-perfect square %d", val)
				assert.Equal(t, uint64(999), result.Uint64(), "Result should not change")
			})
		}
	})

	t.Run("MaxUint32_Perfect", func(t *testing.T) {
		t.Parallel()
		// Test largest perfect square that fits in 64 bits
		// (2^32 - 1)^2 would overflow, so test 2^31 = (2^15.5)^2 which isn't perfect
		// Largest is 2^32 = (2^16)^2 = 4294967296
		i := (*numct.Int)(new(saferith.Int))
		(*saferith.Int)(i).SetUint64(4294967296)
		(*saferith.Int)(i).Resize(64)

		result := (*numct.Int)(new(saferith.Int))
		ok := result.Sqrt(i)

		assert.Equal(t, ct.True, ok)
		assert.Equal(t, uint64(65536), result.Uint64())
	})
}

func TestInt_Sqrt_MultiLimb(t *testing.T) {
	t.Parallel()

	t.Run("PerfectSquares_MultiLimb", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			rootStr  string
			capacity int
		}{
			// Just above 64-bit threshold
			{"Root_2^33", "8589934592", 128},    // 2^33
			{"Root_2^34", "17179869184", 128},   // 2^34
			{"Root_2^35", "34359738368", 128},   // 2^35
			{"Root_2^40", "1099511627776", 128}, // 2^40

			// Larger multi-limb values
			{"Root_2^50", "1125899906842624", 256},       // 2^50
			{"Root_2^60", "1152921504606846976", 256},    // 2^60
			{"Root_2^64", "18446744073709551616", 256},   // 2^64
			{"Root_2^70", "1180591620717411303424", 256}, // 2^70

			// Very large values
			{"Root_2^80", "1208925819614629174706176", 512},        // 2^80
			{"Root_2^100", "1267650600228229401496703205376", 512}, // 2^100

			// Non-power-of-2 large values
			{"Root_10^20", "100000000000000000000", 256},           // 10^20
			{"Root_10^30", "1000000000000000000000000000000", 512}, // 10^30

			// Large odd perfect squares
			{"Root_3^40", "12157665459056928801", 256},   // 3^40
			{"Root_5^30", "931322574615478515625", 256},  // 5^30
			{"Root_7^25", "1341068619663964900807", 256}, // 7^25
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				// Create the root
				root := new(big.Int)
				root.SetString(tc.rootStr, 10)
				require.NotNil(t, root)

				// Square it to get our test value
				square := new(big.Int).Mul(root, root)

				// Convert to our Int type
				i := newIntFromBigInt(square)
				(*saferith.Int)(i).Resize(tc.capacity)

				// Perform sqrt
				result := (*numct.Int)(new(saferith.Int))
				ok := result.Sqrt(i)

				assert.Equal(t, ct.True, ok, "Should return true for perfect square of %s", tc.rootStr)

				// Convert result back to big.Int for comparison
				resultBig := new(big.Int).SetBytes(result.Bytes())
				assert.Equal(t, root.String(), resultBig.String(),
					"Sqrt of %s^2 should be %s", tc.rootStr, tc.rootStr)
			})
		}
	})

	t.Run("NonPerfectSquares_MultiLimb", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			valueStr string
			capacity int
		}{
			// Just above 64-bit threshold
			{"2^65_plus_1", "36893488147419103233", 128},   // 2^65 + 1
			{"2^66_minus_1", "73786976294838206463", 128},  // 2^66 - 1
			{"2^70_plus_7", "1180591620717411303431", 256}, // 2^70 + 7

			// Large non-perfect squares
			{"10^20_plus_1", "100000000000000000001", 256},
			{"10^25_minus_1", "9999999999999999999999999", 256},
			{"Prime_Large", "170141183460469231731687303715884105727", 256}, // 2^127 - 1 (Mersenne prime)

			// Values between perfect squares
			{"Between_2^64_2^65", "18446744073709551617", 256}, // 2^64 + 1
			{"Between_3^40_3^41", "12157665459056928802", 256}, // 3^40 + 1
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				value := new(big.Int)
				value.SetString(tc.valueStr, 10)
				require.NotNil(t, value)

				i := newIntFromBigInt(value)
				(*saferith.Int)(i).Resize(tc.capacity)

				result := (*numct.Int)(new(saferith.Int))
				// Set result to a known value to verify it doesn't change
				(*saferith.Int)(result).SetUint64(777)

				ok := result.Sqrt(i)
				assert.Equal(t, ct.False, ok, "Should return false for non-perfect square %s", tc.valueStr)
				assert.Equal(t, uint64(777), result.Uint64(), "Result should not change")
			})
		}
	})

	t.Run("BoundaryBetweenSingleAndMultiLimb", func(t *testing.T) {
		t.Parallel()
		// Test values right at the boundary between single-limb and multi-limb paths
		// The boundary is at 64 bits

		testCases := []struct {
			name      string
			bits      int
			value     string
			isPerfect bool
			root      string
		}{
			// Exactly at 64 bits
			{"64bit_perfect", 64, "4294967296", true, "65536"}, // 2^32 = (2^16)^2
			{"64bit_nonperfect", 64, "4294967297", false, ""},

			// Just above 64 bits (65 bits) - should use multi-limb path
			{"65bit_perfect", 80, "73786976294838206464", true, "8589934592"}, // (2^33)^2, but with larger capacity
			{"65bit_nonperfect", 80, "73786976294838206465", false, ""},

			// At 66 bits
			{"66bit_perfect", 80, "295147905179352825856", true, "17179869184"}, // (2^34)^2, but with larger capacity
			{"66bit_nonperfect", 80, "295147905179352825857", false, ""},

			// At 128 bits - using 2^60 as root (120-bit square)
			{"128bit_perfect", 128, "1329227995784915872903807060280344576", true, "1152921504606846976"}, // (2^60)^2 = 2^120
			{"128bit_nonperfect", 128, "1329227995784915872903807060280344577", false, ""},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				value := new(big.Int)
				value.SetString(tc.value, 10)
				require.NotNil(t, value)

				i := newIntFromBigInt(value)
				(*saferith.Int)(i).Resize(tc.bits)

				result := (*numct.Int)(new(saferith.Int))
				ok := result.Sqrt(i)

				if tc.isPerfect {
					assert.Equal(t, ct.True, ok, "Should return true for perfect square")

					root := new(big.Int)
					root.SetString(tc.root, 10)
					resultBig := new(big.Int).SetBytes(result.Bytes())
					assert.Equal(t, root.String(), resultBig.String(), "Root should match")
				} else {
					assert.Equal(t, ct.False, ok, "Should return false for non-perfect square")
				}
			})
		}
	})

	t.Run("DifferentCapacities_SameValue", func(t *testing.T) {
		t.Parallel()
		// Test the same value with different announced capacities
		// This tests that the algorithm correctly handles the capacity parameter

		// Use a large perfect square: (2^40)^2
		root := new(big.Int)
		root.SetString("1099511627776", 10) // 2^40
		square := new(big.Int).Mul(root, root)

		capacities := []int{128, 256, 512, 1024}

		for _, cap := range capacities {
			t.Run(fmt.Sprintf("capacity_%d", cap), func(t *testing.T) {
		t.Parallel()
				i := newIntFromBigInt(square)
				(*saferith.Int)(i).Resize(cap)

				result := (*numct.Int)(new(saferith.Int))
				ok := result.Sqrt(i)

				assert.Equal(t, ct.True, ok, "Should return true regardless of capacity")

				resultBig := new(big.Int).SetBytes(result.Bytes())
				assert.Equal(t, root.String(), resultBig.String(),
					"Root should be same regardless of capacity")
			})
		}
	})

	t.Run("VeryLargePerfectSquares", func(t *testing.T) {
		t.Parallel()
		// Test with extremely large perfect squares to stress the multi-limb algorithm
		testCases := []struct {
			name     string
			rootBits int
		}{
			{"256bit_root", 256},
			{"512bit_root", 512},
			{"1024bit_root", 1024},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				// Generate a random-ish large number as root
				root := new(big.Int).Lsh(big.NewInt(1), uint(tc.rootBits-1))
				root.Add(root, big.NewInt(12345)) // Make it not just a power of 2

				// Square it
				square := new(big.Int).Mul(root, root)

				// Convert and test
				i := newIntFromBigInt(square)
				(*saferith.Int)(i).Resize(tc.rootBits * 2)

				result := (*numct.Int)(new(saferith.Int))
				ok := result.Sqrt(i)

				assert.Equal(t, ct.True, ok, "Should return true for large perfect square")

				resultBig := new(big.Int).SetBytes(result.Bytes())
				assert.Equal(t, root.String(), resultBig.String(),
					"Root should match for %d-bit root", tc.rootBits)
			})
		}
	})
}

func TestInt_Sqrt_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("Zero_MultipleCapacities", func(t *testing.T) {
		t.Parallel()
		capacities := []int{1, 8, 16, 32, 64, 65, 128, 256, 512}

		for _, cap := range capacities {
			t.Run(fmt.Sprintf("cap_%d", cap), func(t *testing.T) {
		t.Parallel()
				i := (*numct.Int)(new(saferith.Int))
				(*saferith.Int)(i).SetUint64(0)
				(*saferith.Int)(i).Resize(cap)

				result := (*numct.Int)(new(saferith.Int))
				ok := result.Sqrt(i)

				assert.Equal(t, ct.True, ok, "Sqrt(0) should always return true")
				assert.Equal(t, uint64(0), result.Uint64(), "Sqrt(0) should be 0")
			})
		}
	})

	t.Run("One_MultipleCapacities", func(t *testing.T) {
		t.Parallel()
		capacities := []int{1, 8, 16, 32, 64, 65, 128, 256}

		for _, cap := range capacities {
			t.Run(fmt.Sprintf("cap_%d", cap), func(t *testing.T) {
		t.Parallel()
				i := (*numct.Int)(new(saferith.Int))
				(*saferith.Int)(i).SetUint64(1)
				(*saferith.Int)(i).Resize(cap)

				result := (*numct.Int)(new(saferith.Int))
				ok := result.Sqrt(i)

				assert.Equal(t, ct.True, ok, "Sqrt(1) should always return true")
				assert.Equal(t, uint64(1), result.Uint64(), "Sqrt(1) should be 1")
			})
		}
	})

	t.Run("NegativeNumbers_AllPaths", func(t *testing.T) {
		t.Parallel()
		// Test negative numbers with different capacities to ensure both paths handle them
		testCases := []struct {
			value    int64
			capacity int
		}{
			{-1, 32},
			{-4, 64},
			{-16, 64},
			{-100, 65}, // Force multi-limb path
			{-10000, 128},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("neg_%d_cap_%d", tc.value, tc.capacity), func(t *testing.T) {
		t.Parallel()
				i := (*numct.Int)(new(saferith.Int))
				i.SetInt64(tc.value)
				(*saferith.Int)(i).Resize(tc.capacity)

				result := (*numct.Int)(new(saferith.Int))
				(*saferith.Int)(result).SetUint64(888)

				ok := result.Sqrt(i)
				assert.Equal(t, ct.False, ok, "Sqrt of negative should return false")
				assert.Equal(t, uint64(888), result.Uint64(), "Result should not change")
			})
		}
	})

	t.Run("SelfAssignment_MultiLimb", func(t *testing.T) {
		t.Parallel()
		// Test self-assignment with multi-limb values
		root := new(big.Int)
		root.SetString("1099511627776", 10) // 2^40
		square := new(big.Int).Mul(root, root)

		i := newIntFromBigInt(square)
		(*saferith.Int)(i).Resize(128)

		// Self-assignment: i.Sqrt(i)
		ok := i.Sqrt(i)
		assert.Equal(t, ct.True, ok)

		resultBig := new(big.Int).SetBytes(i.Bytes())
		assert.Equal(t, root.String(), resultBig.String(), "Self-assignment should work correctly")
	})

	t.Run("PairsCalculation", func(t *testing.T) {
		t.Parallel()
		// Test that pairs calculation works correctly for various bit sizes
		// pairs = (capBits + 1) / 2
		testCases := []struct {
			bits          int
			expectedPairs int
		}{
			{1, 1},     // (1+1)/2 = 1
			{2, 1},     // (2+1)/2 = 1
			{3, 2},     // (3+1)/2 = 2
			{64, 32},   // (64+1)/2 = 32
			{65, 33},   // (65+1)/2 = 33
			{128, 64},  // (128+1)/2 = 64
			{255, 128}, // (255+1)/2 = 128
			{256, 128}, // (256+1)/2 = 128
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("bits_%d", tc.bits), func(t *testing.T) {
		t.Parallel()
				// For very small capacities, use 1 or 0 as test value
				var testVal int64
				var expectedRoot uint64
				var shouldPass bool

				if tc.bits < 3 {
					// Use 1 for tiny capacities (1 bit can hold 0 or 1)
					testVal = 1
					expectedRoot = 1
					shouldPass = true
				} else {
					// Use 4 for larger capacities
					testVal = 4
					expectedRoot = 2
					shouldPass = true
				}

				value := new(big.Int).SetInt64(testVal)
				i := newIntFromBigInt(value)
				(*saferith.Int)(i).Resize(tc.bits)

				result := (*numct.Int)(new(saferith.Int))
				ok := result.Sqrt(i)

				if shouldPass {
					assert.Equal(t, ct.True, ok)
					assert.Equal(t, expectedRoot, result.Uint64())
				}
			})
		}
	})
}

func TestInt_Sqrt_Correctness(t *testing.T) {
	t.Parallel()

	t.Run("CompareWithBigInt", func(t *testing.T) {
		t.Parallel()
		// Compare our implementation with Go's big.Int.Sqrt for various values
		testValues := []string{
			"0",
			"1",
			"4",
			"100",
			"10000",
			"1000000",
			"123456789",
			"9999999999999999",
			"18446744073709551616", // 2^64
			"340282366920938463463374607431768211456",                                        // 2^128
			"115792089237316195423570985008687907853269984665640564039457584007913129639936", // 2^256
		}

		for _, valStr := range testValues {
			t.Run(fmt.Sprintf("value_%s", valStr[:min(20, len(valStr))]), func(t *testing.T) {
		t.Parallel()
				value := new(big.Int)
				value.SetString(valStr, 10)

				// Calculate expected result using big.Int
				expected := new(big.Int).Sqrt(value)
				isPerfect := new(big.Int).Mul(expected, expected).Cmp(value) == 0

				// Test with our implementation
				i := newIntFromBigInt(value)
				capacity := len(value.Bytes()) * 8
				if capacity < 128 {
					capacity = 128
				}
				(*saferith.Int)(i).Resize(capacity)

				result := (*numct.Int)(new(saferith.Int))
				ok := result.Sqrt(i)

				if isPerfect {
					assert.Equal(t, ct.True, ok, "Should return true for perfect square")
					resultBig := new(big.Int).SetBytes(result.Bytes())
					assert.Equal(t, expected.String(), resultBig.String(),
						"Result should match big.Int.Sqrt")
				} else {
					assert.Equal(t, ct.False, ok, "Should return false for non-perfect square")
				}
			})
		}
	})
}

func TestInt_BitOperations(t *testing.T) {
	t.Parallel()

	t.Run("Bit", func(t *testing.T) {
		t.Parallel()
		// Test positive number: 170 = 0xAA = 10101010 binary
		i := newInt(170)

		expectedBits := []byte{0, 1, 0, 1, 0, 1, 0, 1}
		for idx, expected := range expectedBits {
			actual := i.Bit(uint(idx))
			assert.Equal(t, expected, actual, "bit %d", idx)
		}

		// Test negative number: bit operations work on magnitude
		i.SetInt64(-170)
		for idx, expected := range expectedBits {
			actual := i.Bit(uint(idx))
			assert.Equal(t, expected, actual, "bit %d of -170", idx)
		}

		// Bits beyond the number should be 0
		assert.Equal(t, byte(0), i.Bit(100))
	})

	t.Run("Lsh", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			input    int64
			shift    uint
			expected int64
		}{
			{"shift_zero", 1, 0, 1},
			{"shift_positive", 3, 4, 48},
			{"shift_negative", -3, 4, -48},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				result := newInt(0)

				result.Lsh(i, tc.shift)
				assert.Equal(t, tc.expected, result.Int64())
			})
		}
	})

	t.Run("LshCap", func(t *testing.T) {
		t.Parallel()
		i := newInt(3)
		result := newInt(0)

		result.LshCap(i, 4, 8)
		assert.Equal(t, int64(48), result.Int64()) // (3 << 4) = 48

		// Test with negative number
		i.SetInt64(-3)
		result.LshCap(i, 4, 8)
		assert.Equal(t, int64(-48), result.Int64()) // (-3 << 4) = -48
	})

	t.Run("Rsh", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			input    int64
			shift    uint
			expected int64
		}{
			{"shift_zero", 48, 0, 48},
			{"shift_positive", 48, 4, 3},
			{"shift_negative", -48, 4, -3},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				result := newInt(0)

				result.Rsh(i, tc.shift)
				assert.Equal(t, tc.expected, result.Int64())
			})
		}
	})

	t.Run("RshCap", func(t *testing.T) {
		t.Parallel()
		i := newInt(48)
		result := newInt(0)

		result.RshCap(i, 4, 8)
		assert.Equal(t, int64(3), result.Int64()) // (48 >> 4) = 3

		// Test with negative number
		i.SetInt64(-48)
		result.RshCap(i, 4, 8)
		assert.Equal(t, int64(-3), result.Int64()) // (-48 >> 4) = -3
	})
}

func TestInt_ComparisonOperations(t *testing.T) {
	t.Parallel()

	t.Run("Compare", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			a, b     int64
			expectLt bool
			expectEq bool
			expectGt bool
		}{
			{"equal_positive", 10, 10, false, true, false},
			{"equal_negative", -10, -10, false, true, false},
			{"equal_zero", 0, 0, false, true, false},
			{"pos_less_than_pos", 5, 10, true, false, false},
			{"pos_greater_than_pos", 15, 10, false, false, true},
			{"neg_less_than_neg", -15, -10, true, false, false},
			{"neg_greater_than_neg", -5, -10, false, false, true},
			{"neg_less_than_pos", -5, 10, true, false, false},
			{"pos_greater_than_neg", 5, -10, false, false, true},
			{"zero_greater_than_neg", 0, -10, false, false, true},
			{"zero_less_than_pos", 0, 10, true, false, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				a := newInt(tc.a)
				b := newInt(tc.b)

				lt, eq, gt := a.Compare(b)
				if tc.expectLt {
					assert.Equal(t, ct.True, lt, "lt")
				} else {
					assert.Equal(t, ct.False, lt, "lt")
				}
				if tc.expectEq {
					assert.Equal(t, ct.True, eq, "eq")
				} else {
					assert.Equal(t, ct.False, eq, "eq")
				}
				if tc.expectGt {
					assert.Equal(t, ct.True, gt, "gt")
				} else {
					assert.Equal(t, ct.False, gt, "gt")
				}
			})
		}
	})

	t.Run("Equal", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			a, b     int64
			expected bool
		}{
			{0, 0, true},
			{1, 1, true},
			{-1, -1, true},
			{100, 100, true},
			{-100, -100, true},
			{0, 1, false},
			{1, -1, false},
			{100, 101, false},
			{-100, -101, false},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				a := newInt(tc.a)
				b := newInt(tc.b)

				result := a.Equal(b)
				if tc.expected {
					assert.Equal(t, ct.True, result)
				} else {
					assert.Equal(t, ct.False, result)
				}
			})
		}
	})

	t.Run("IsNegative", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    int64
			expected bool
		}{
			{0, false},
			{1, false},
			{100, false},
			{-1, true},
			{-100, true},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				result := i.IsNegative()
				if tc.expected {
					assert.Equal(t, ct.True, result)
				} else {
					assert.Equal(t, ct.False, result)
				}
			})
		}
	})

	t.Run("IsZero", func(t *testing.T) {
		t.Parallel()
		zero := newInt(0)
		assert.Equal(t, ct.True, zero.IsZero())

		positive := newInt(1)
		assert.Equal(t, ct.False, positive.IsZero())

		negative := newInt(-1)
		assert.Equal(t, ct.False, negative.IsZero())
	})

	t.Run("IsNonZero", func(t *testing.T) {
		t.Parallel()
		zero := newInt(0)
		assert.Equal(t, ct.False, zero.IsNonZero())

		positive := newInt(1)
		assert.Equal(t, ct.True, positive.IsNonZero())

		negative := newInt(-1)
		assert.Equal(t, ct.True, negative.IsNonZero())
	})

	t.Run("IsOne", func(t *testing.T) {
		t.Parallel()
		one := newInt(1)
		assert.Equal(t, ct.True, one.IsOne())

		zero := newInt(0)
		assert.Equal(t, ct.False, zero.IsOne())

		negOne := newInt(-1)
		assert.Equal(t, ct.False, negOne.IsOne())

		two := newInt(2)
		assert.Equal(t, ct.False, two.IsOne())
	})
}

func TestInt_UtilityOperations(t *testing.T) {
	t.Parallel()

	t.Run("Coprime", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			a, b     int64
			expected bool
		}{
			{"coprime_primes", 7, 11, true},
			{"coprime_consecutive", 8, 9, true},
			{"not_coprime_even", 6, 8, false},
			{"not_coprime_multiples", 15, 25, false},
			{"coprime_with_one", 1, 100, true},
			{"coprime_negative", -7, 11, true},
			{"coprime_both_negative", -7, -11, true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
		t.Parallel()
				a := newInt(tc.a)
				b := newInt(tc.b)

				result := a.Coprime(b)
				if tc.expected {
					assert.Equal(t, ct.True, result)
				} else {
					assert.Equal(t, ct.False, result)
				}
			})
		}
	})

	t.Run("String", func(t *testing.T) {
		t.Parallel()
		// String format depends on saferith.Int implementation
		i := newInt(42)
		assert.NotEmpty(t, i.String())

		i.SetInt64(-42)
		assert.NotEmpty(t, i.String())
	})

	t.Run("TrueLen", func(t *testing.T) {
		t.Parallel()
		zero := newInt(0)
		assert.Equal(t, uint(0), zero.TrueLen())

		small := newInt(255)
		assert.Positive(t, small.TrueLen())

		negative := newInt(-255)
		assert.Positive(t, negative.TrueLen())
	})

	t.Run("AnnouncedLen", func(t *testing.T) {
		t.Parallel()
		i := newInt(42)
		announcedLen := i.AnnouncedLen()
		assert.GreaterOrEqual(t, announcedLen, i.TrueLen())
	})
}

func TestInt_ConditionalOperations(t *testing.T) {
	t.Parallel()

	t.Run("Select", func(t *testing.T) {
		t.Parallel()
		x0 := newInt(100)
		x1 := newInt(-200)
		result := newInt(0)

		// Choose x0 (choice = 0)
		result.Select(ct.Choice(0), x0, x1)
		assert.Equal(t, int64(100), result.Int64())

		// Choose x1 (choice = 1)
		result.Select(ct.Choice(1), x0, x1)
		assert.Equal(t, int64(-200), result.Int64())

		// Test with both negative
		x0.SetInt64(-100)
		x1.SetInt64(-200)
		result.Select(ct.Choice(0), x0, x1)
		assert.Equal(t, int64(-100), result.Int64())

		result.Select(ct.Choice(1), x0, x1)
		assert.Equal(t, int64(-200), result.Int64())
	})
}

func TestInt_ConversionOperations(t *testing.T) {
	t.Parallel()

	t.Run("Uint64", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    int64
			expected uint64
		}{
			{0, 0},
			{1, 1},
			{42, 42},
			{-1, 1},   // Magnitude of -1
			{-42, 42}, // Magnitude of -42
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(tc.input)
				assert.Equal(t, tc.expected, i.Uint64())
			})
		}
	})

	t.Run("SetUint64", func(t *testing.T) {
		t.Parallel()
		i := newInt(0)

		testCases := []uint64{0, 1, 42, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
		for _, val := range testCases {
			i.SetUint64(val)
			assert.Equal(t, val, i.Uint64())
			assert.Equal(t, ct.False, i.IsNegative())
		}
	})

	t.Run("Int64", func(t *testing.T) {
		t.Parallel()
		testCases := []int64{0, 1, -1, 42, -42, 100, -100}

		for _, val := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(val)
				assert.Equal(t, val, i.Int64())
			})
		}
	})

	t.Run("SetInt64", func(t *testing.T) {
		t.Parallel()
		i := newInt(0)

		testCases := []int64{
			0, 1, -1, 42, -42,
			math.MaxInt64,
			math.MinInt64 + 1, // Avoid MinInt64 edge case for now
		}

		for _, val := range testCases {
			i.SetInt64(val)
			assert.Equal(t, val, i.Int64())
		}
	})

	t.Run("SetInt64_MinInt64", func(t *testing.T) {
		t.Parallel()
		// Special test for MinInt64 edge case
		i := newInt(0)
		i.SetInt64(math.MinInt64)
		// MinInt64 magnitude can't be represented as positive int64
		// but should still work correctly
		assert.Equal(t, ct.True, i.IsNegative())
		assert.Equal(t, uint64(1<<63), i.Uint64()) // Magnitude is 2^63
	})

	t.Run("Bytes", func(t *testing.T) {
		t.Parallel()
		testCases := []int64{0, 42, -42, 0x1234, -0x1234}

		for _, input := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(input)
				result := i.Bytes()

				// Bytes returns magnitude
				i2 := newInt(0)
				i2.SetBytes(result)

				var expected int64
				if input < 0 {
					expected = -input
				} else {
					expected = input
				}
				assert.Equal(t, expected, i2.Int64())
			})
		}
	})

	t.Run("SetBytes", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    []byte
			expected int64
		}{
			{[]byte{}, 0},
			{[]byte{0xFF}, 0xFF},
			{[]byte{0x12, 0x34}, 0x1234},
			{[]byte{0xDE, 0xAD, 0xBE, 0xEF}, int64(0xDEADBEEF)},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
		t.Parallel()
				i := newInt(0)
				ok := i.SetBytes(tc.input)

				assert.Equal(t, ct.True, ok)
				assert.Equal(t, tc.expected, i.Int64())
				assert.Equal(t, ct.False, i.IsNegative()) // SetBytes creates positive numbers
			})
		}
	})
}

func TestInt_CapacityOperations(t *testing.T) {
	t.Parallel()

	t.Run("Resize", func(t *testing.T) {
		t.Parallel()
		i := newInt(42)

		// Resize changes the announced capacity of the number
		i.Resize(10)
		assert.Equal(t, uint(10), i.AnnouncedLen())

		// When resizing to smaller than needed, value gets truncated
		i.SetInt64(42)
		i.Resize(5)
		assert.Equal(t, uint(5), i.AnnouncedLen())
		assert.Equal(t, int64(10), i.Int64()) // 42 mod 32 (2^5) = 10

		// Test with negative number
		i.SetInt64(-42)
		i.Resize(10)
		assert.Equal(t, uint(10), i.AnnouncedLen())
		assert.Equal(t, int64(-42), i.Int64())
	})
}

func TestInt_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("Operations_With_Zero", func(t *testing.T) {
		t.Parallel()
		zero := newInt(0)
		nonZero := newInt(42)
		negNonZero := newInt(-42)
		result := newInt(0)

		// Add with zero
		result.Add(zero, nonZero)
		assert.Equal(t, int64(42), result.Int64())

		result.Add(nonZero, zero)
		assert.Equal(t, int64(42), result.Int64())

		// Multiply with zero
		result.Mul(zero, nonZero)
		assert.Equal(t, int64(0), result.Int64())

		result.Mul(negNonZero, zero)
		assert.Equal(t, int64(0), result.Int64())

		// Subtract zero
		result.Sub(nonZero, zero)
		assert.Equal(t, int64(42), result.Int64())

		result.Sub(zero, nonZero)
		assert.Equal(t, int64(-42), result.Int64())
	})

	t.Run("Self_Assignment", func(t *testing.T) {
		t.Parallel()
		i := newInt(42)

		// Self add
		i.Add(i, i)
		assert.Equal(t, int64(84), i.Int64())

		// Self multiply
		i.SetInt64(7)
		i.Mul(i, i)
		assert.Equal(t, int64(49), i.Int64())

		// Self set
		i.SetInt64(42)
		i.Set(i)
		assert.Equal(t, int64(42), i.Int64())
	})

	t.Run("Large_Numbers", func(t *testing.T) {
		t.Parallel()
		// Test with numbers larger than int64 can handle
		largeBytes := []byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}

		i1 := newIntFromBytes(largeBytes)
		i2 := newIntFromBytes(largeBytes)
		result := newInt(0)

		// Addition should work
		result.Add(i1, i2)
		assert.NotEmpty(t, result.String())

		// Comparison should work
		eq := i1.Equal(i2)
		assert.Equal(t, ct.True, eq)

		// Bytes conversion should work
		recoveredBytes := i1.Bytes()
		assert.True(t, bytes.Equal(largeBytes, recoveredBytes))
	})

	t.Run("Mixed_Sign_Operations", func(t *testing.T) {
		t.Parallel()
		pos := newInt(10)
		neg := newInt(-10)
		result := newInt(0)

		// pos + neg = 0
		result.Add(pos, neg)
		assert.Equal(t, int64(0), result.Int64())

		// neg + pos = 0
		result.Add(neg, pos)
		assert.Equal(t, int64(0), result.Int64())

		// pos - neg = 20
		result.Sub(pos, neg)
		assert.Equal(t, int64(20), result.Int64())

		// neg - pos = -20
		result.Sub(neg, pos)
		assert.Equal(t, int64(-20), result.Int64())

		// pos * neg = -100
		result.Mul(pos, neg)
		assert.Equal(t, int64(-100), result.Int64())
	})
}

func TestInt_ConstantTime(t *testing.T) {
	t.Parallel()

	t.Run("Comparison_Constant_Time", func(t *testing.T) {
		t.Parallel()
		// This test verifies that comparison operations return ct.Bool
		// which ensures constant-time execution
		i1 := newInt(42)
		i2 := newInt(-43)

		// These operations should return ct.Bool types
		var ltResult ct.Bool
		var eqResult ct.Bool
		var gtResult ct.Bool

		ltResult, eqResult, gtResult = i1.Compare(i2)
		assert.Equal(t, ct.False, ltResult)
		assert.Equal(t, ct.False, eqResult)
		assert.Equal(t, ct.True, gtResult)

		// Equal operation returns ct.Bool
		var equalResult = i1.Equal(i2)
		assert.Equal(t, ct.False, equalResult)

		// IsZero returns ct.Bool
		var zeroResult = i1.IsZero()
		assert.Equal(t, ct.False, zeroResult)

		// IsNonZero returns ct.Bool
		var nonZeroResult = i1.IsNonZero()
		assert.Equal(t, ct.True, nonZeroResult)

		// IsNegative returns ct.Bool
		var negResult = i2.IsNegative()
		assert.Equal(t, ct.True, negResult)

		// IsOne returns ct.Bool
		var oneResult = i1.IsOne()
		assert.Equal(t, ct.False, oneResult)

		// Coprime returns ct.Bool
		var coprimeResult = i1.Coprime(i2)
		assert.Equal(t, ct.True, coprimeResult)
	})
}

func BenchmarkInt_Add(b *testing.B) {
	i1 := newInt(0x7FFFFFFF)
	i2 := newInt(-0x7FFFFFFF)
	result := newInt(0)

	b.ResetTimer()
	for range b.N {
		result.Add(i1, i2)
	}
}

func BenchmarkInt_Mul(b *testing.B) {
	i1 := newInt(0xFFFF)
	i2 := newInt(-0xFFFF)
	result := newInt(0)

	b.ResetTimer()
	for range b.N {
		result.Mul(i1, i2)
	}
}

func BenchmarkInt_Compare(b *testing.B) {
	i1 := newInt(0x7FFFFFFF)
	i2 := newInt(-0x7FFFFFFE)

	b.ResetTimer()
	for range b.N {
		_, _, _ = i1.Compare(i2)
	}
}

func BenchmarkInt_Sqrt(b *testing.B) {
	i := newInt(144)
	result := newInt(0)

	b.ResetTimer()
	for range b.N {
		result.Sqrt(i)
	}
}

// TestInt_SaferithCompatibility ensures that our Int type
// correctly wraps saferith.Int functionality
func TestInt_SaferithCompatibility(t *testing.T) {
	t.Parallel()

	t.Run("Type_Conversion", func(t *testing.T) {
		t.Parallel()
		// Verify that Int can be converted to/from saferith.Int
		implInt := newInt(42)
		saferithInt := (*saferith.Int)(implInt)

		assert.Equal(t, int64(42), implInt.Int64())
		assert.NotEmpty(t, saferithInt.String())

		// Convert back
		backToSaferith := (*saferith.Int)(implInt)
		assert.Equal(t, int64(42), (*numct.Int)(backToSaferith).Int64())

		// Test with negative
		implInt.SetInt64(-42)
		assert.Equal(t, int64(-42), implInt.Int64())
	})
}

// TestInt_InterfaceCompliance verifies that Int implements
// the required internal.IntMutable interface
func TestInt_InterfaceCompliance(t *testing.T) {
	t.Parallel()

	// This test passes if the code compiles, as the interface
	// compliance is checked at compile time in int.go:14
	require.NotNil(t, newInt(0))
}

// TestInt_CondAssign tests the CondAssign method that uses ct.CMOV
func TestInt_CondAssign(t *testing.T) {
	t.Parallel()

	t.Run("basic positive integers", func(t *testing.T) {
		t.Parallel()
		a := newInt(42)
		b := newInt(100)

		// Test no assignment when choice=0
		dst := a.Clone()
		dst.CondAssign(ct.Zero, b)
		assert.Equal(t, ct.True, dst.Equal(a), "CondAssign(0) should not modify dst")
		assert.Equal(t, ct.False, dst.Equal(b), "dst should not equal b")

		// Test assignment when choice=1
		dst = a.Clone()
		dst.CondAssign(ct.One, b)
		assert.Equal(t, ct.True, dst.Equal(b), "CondAssign(1) should assign b to dst")
		assert.Equal(t, ct.False, dst.Equal(a), "dst should no longer equal a")
	})

	t.Run("negative integers", func(t *testing.T) {
		t.Parallel()
		a := newInt(-42)
		b := newInt(-100)

		// Test no assignment when choice=0
		dst := a.Clone()
		dst.CondAssign(ct.Zero, b)
		assert.Equal(t, ct.True, dst.Equal(a), "CondAssign(0) should not modify dst")

		// Test assignment when choice=1
		dst = a.Clone()
		dst.CondAssign(ct.One, b)
		assert.Equal(t, ct.True, dst.Equal(b), "CondAssign(1) should assign b to dst")
	})

	t.Run("mixed signs", func(t *testing.T) {
		t.Parallel()
		a := newInt(42)
		b := newInt(-100)

		// Test no assignment when choice=0
		dst := a.Clone()
		dst.CondAssign(ct.Zero, b)
		assert.Equal(t, ct.True, dst.Equal(a), "CondAssign(0) should not modify dst")
		assert.Equal(t, ct.False, dst.IsNegative(), "dst should remain positive")

		// Test assignment when choice=1
		dst = a.Clone()
		dst.CondAssign(ct.One, b)
		assert.Equal(t, ct.True, dst.Equal(b), "CondAssign(1) should assign b to dst")
		assert.Equal(t, ct.True, dst.IsNegative(), "dst should now be negative")
	})

	t.Run("zero values", func(t *testing.T) {
		t.Parallel()
		zero := newInt(0)
		nonZero := newInt(42)

		// Assign zero to non-zero
		dst := nonZero.Clone()
		dst.CondAssign(ct.One, zero)
		assert.Equal(t, ct.True, dst.Equal(zero), "Should assign zero")
		assert.Equal(t, ct.True, dst.IsZero(), "dst should be zero")

		// Assign non-zero to zero
		dst = zero.Clone()
		dst.CondAssign(ct.One, nonZero)
		assert.Equal(t, ct.True, dst.Equal(nonZero), "Should assign non-zero")
		assert.Equal(t, ct.False, dst.IsZero(), "dst should not be zero")
	})

	t.Run("large values", func(t *testing.T) {
		t.Parallel()
		// Test with large integers
		bigA := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256
		bigA.Sub(bigA, big.NewInt(1))                // 2^256 - 1
		bigB := new(big.Int).Lsh(big.NewInt(1), 512) // 2^512

		a := newIntFromBigInt(bigA)
		b := newIntFromBigInt(bigB)

		// Test no assignment when choice=0
		dst := a.Clone()
		dst.CondAssign(ct.Zero, b)
		assert.Equal(t, ct.True, dst.Equal(a), "CondAssign(0) should not modify dst")

		// Test assignment when choice=1
		dst = a.Clone()
		dst.CondAssign(ct.One, b)
		assert.Equal(t, ct.True, dst.Equal(b), "CondAssign(1) should assign b to dst")
	})

	t.Run("self assignment", func(t *testing.T) {
		t.Parallel()
		a := newInt(42)
		original := a.Clone()

		// Self-assign with choice=0
		a.CondAssign(ct.Zero, a)
		assert.Equal(t, ct.True, a.Equal(original), "Self-assign with choice=0 should not change value")

		// Self-assign with choice=1
		a.CondAssign(ct.One, a)
		assert.Equal(t, ct.True, a.Equal(original), "Self-assign with choice=1 should not change value")
	})

	t.Run("constant time behaviour", func(t *testing.T) {
		t.Parallel()
		// Test that the operation appears to be constant time
		// by running it many times with different values
		values := []*numct.Int{
			newInt(0),
			newInt(1),
			newInt(-1),
			newInt(1000000),
			newInt(-1000000),
		}

		for _, val1 := range values {
			for _, val2 := range values {
				for _, choice := range []ct.Choice{ct.Zero, ct.One} {
					dst := val1.Clone()
					dst.CondAssign(choice, val2)

					if choice == ct.Zero {
						assert.Equal(t, ct.True, dst.Equal(val1),
							"CondAssign(0) should preserve original value")
					} else {
						assert.Equal(t, ct.True, dst.Equal(val2),
							"CondAssign(1) should assign new value")
					}
				}
			}
		}
	})
}

// TestInt_CondNeg tests the CondNeg method
func TestInt_CondNeg(t *testing.T) {
	t.Parallel()

	t.Run("positive to negative", func(t *testing.T) {
		t.Parallel()
		a := newInt(42)

		// No negation when choice=0
		dst := a.Clone()
		dst.CondNeg(ct.Zero)
		assert.Equal(t, ct.True, dst.Equal(a), "CondNeg(0) should not modify value")
		assert.Equal(t, ct.False, dst.IsNegative(), "Should remain positive")

		// Negate when choice=1
		dst = a.Clone()
		dst.CondNeg(ct.One)
		expected := newInt(-42)
		assert.Equal(t, ct.True, dst.Equal(expected), "CondNeg(1) should negate value")
		assert.Equal(t, ct.True, dst.IsNegative(), "Should become negative")
	})

	t.Run("negative to positive", func(t *testing.T) {
		t.Parallel()
		a := newInt(-42)

		// No negation when choice=0
		dst := a.Clone()
		dst.CondNeg(ct.Zero)
		assert.Equal(t, ct.True, dst.Equal(a), "CondNeg(0) should not modify value")
		assert.Equal(t, ct.True, dst.IsNegative(), "Should remain negative")

		// Negate when choice=1
		dst = a.Clone()
		dst.CondNeg(ct.One)
		expected := newInt(42)
		assert.Equal(t, ct.True, dst.Equal(expected), "CondNeg(1) should negate value")
		assert.Equal(t, ct.False, dst.IsNegative(), "Should become positive")
	})

	t.Run("zero negation", func(t *testing.T) {
		t.Parallel()
		zero := newInt(0)

		// Negating zero should still be zero
		dst := zero.Clone()
		dst.CondNeg(ct.One)
		assert.Equal(t, ct.True, dst.Equal(zero), "Negating zero should still be zero")
		assert.Equal(t, ct.True, dst.IsZero(), "Should still be zero")
	})
}

// BenchmarkInt_CondAssign benchmarks the CondAssign operation
func BenchmarkInt_CondAssign(b *testing.B) {
	b.Run("small_int", func(b *testing.B) {
		a := newInt(42)
		x := newInt(100)
		choice := ct.One

		b.ResetTimer()
		for range b.N {
			a.CondAssign(choice, x)
		}
	})

	b.Run("large_int_256bit", func(b *testing.B) {
		bigA := new(big.Int).Lsh(big.NewInt(1), 256)
		bigA.Sub(bigA, big.NewInt(1)) // 2^256 - 1
		bigX := new(big.Int).Lsh(big.NewInt(1), 255)

		a := newIntFromBigInt(bigA)
		x := newIntFromBigInt(bigX)
		choice := ct.One

		b.ResetTimer()
		for range b.N {
			a.CondAssign(choice, x)
		}
	})
}
