package impl_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/impl"
	"github.com/cronokirby/saferith"
)

func newNat(val uint64) *impl.Nat {
	n := (*impl.Nat)(new(saferith.Nat))
	n.SetUint64(val)
	return n
}

func newNatFromBytes(data []byte) *impl.Nat {
	n := (*impl.Nat)(new(saferith.Nat))
	n.SetBytes(data)
	return n
}

// Test DivCap with zero divisor
func TestNat_DivCap_ZeroDivisor(t *testing.T) {
	t.Parallel()

	a := (*impl.Nat)(new(saferith.Nat).SetUint64(10))
	zero := (*impl.Nat)(new(saferith.Nat).SetUint64(0))
	result := (*impl.Nat)(new(saferith.Nat).SetUint64(999)) // Initial value

	ok := result.DivCap(a, zero, -1)

	// Should return false for zero divisor
	assert.Equal(t, ct.False, ok, "DivCap with zero divisor should return false")
	// Result should remain unchanged
	assert.Equal(t, uint64(999), result.Uint64(), "Result should remain unchanged when divisor is zero")
}

// Test DivCap with non-zero divisor
func TestNat_DivCap_NonZeroDivisor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dividend uint64
		divisor  uint64
		wantQuot uint64
		wantOk   ct.Bool
	}{
		{"10/2 exact", 10, 2, 5, ct.True},
		{"10/3 inexact", 10, 3, 0, ct.False}, // DivCap only succeeds for exact division
		{"0/5", 0, 5, 0, ct.True},
		{"15/1", 15, 1, 15, ct.True},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := (*impl.Nat)(new(saferith.Nat).SetUint64(tt.dividend))
			b := (*impl.Nat)(new(saferith.Nat).SetUint64(tt.divisor))
			result := (*impl.Nat)(new(saferith.Nat).SetUint64(999))

			ok := result.DivCap(a, b, -1)

			assert.Equal(t, tt.wantOk, ok, "DivCap ok result")
			if tt.wantOk == ct.True {
				assert.Equal(t, tt.wantQuot, result.Uint64(), "DivCap quotient")
			} else {
				assert.Equal(t, uint64(999), result.Uint64(), "Result should remain unchanged for inexact division")
			}
		})
	}
}

// Test Mod with zero modulus
func TestNat_Mod_ZeroModulus(t *testing.T) {
	t.Parallel()

	a := (*impl.Nat)(new(saferith.Nat).SetUint64(10))
	zero := (*impl.Nat)(new(saferith.Nat).SetUint64(0))
	result := (*impl.Nat)(new(saferith.Nat).SetUint64(999))

	ok := result.Mod(a, zero)

	// Should return false for zero modulus
	assert.Equal(t, ct.False, ok, "Mod with zero modulus should return false")
	// Result should remain unchanged
	assert.Equal(t, uint64(999), result.Uint64(), "Result should remain unchanged when modulus is zero")
}

// Test Mod with non-zero modulus
func TestNat_Mod_NonZeroModulus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   uint64
		modulus uint64
		want    uint64
	}{
		{"10 mod 3", 10, 3, 1},
		{"10 mod 5", 10, 5, 0},
		{"0 mod 5", 0, 5, 0},
		{"15 mod 1", 15, 1, 0}, // Any number mod 1 is 0
		{"7 mod 10", 7, 10, 7},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := (*impl.Nat)(new(saferith.Nat).SetUint64(tt.value))
			m := (*impl.Nat)(new(saferith.Nat).SetUint64(tt.modulus))
			result := (*impl.Nat)(new(saferith.Nat).SetUint64(999))

			ok := result.Mod(a, m)

			assert.Equal(t, ct.True, ok, "Mod with non-zero modulus should return true")
			assert.Equal(t, tt.want, result.Uint64(), "Mod result")
		})
	}
}

// Test DivModCap with zero divisor
func TestNat_DivModCap_ZeroDivisor(t *testing.T) {
	t.Parallel()

	a := (*impl.Nat)(new(saferith.Nat).SetUint64(10))
	zero := (*impl.Nat)(new(saferith.Nat).SetUint64(0))
	quot := (*impl.Nat)(new(saferith.Nat).SetUint64(888))
	rem := (*impl.Nat)(new(saferith.Nat).SetUint64(999))

	// This is a method on Nat but doesn't use the receiver
	dummy := (*impl.Nat)(new(saferith.Nat))
	ok := dummy.DivModCap(quot, rem, a, zero, -1)

	// Should return false for zero divisor
	assert.Equal(t, ct.False, ok, "DivModCap with zero divisor should return false")
	// Results should remain unchanged
	assert.Equal(t, uint64(888), quot.Uint64(), "Quotient should remain unchanged when divisor is zero")
	assert.Equal(t, uint64(999), rem.Uint64(), "Remainder should remain unchanged when divisor is zero")
}

// Test DivModCap with non-zero divisor
func TestNat_DivModCap_NonZeroDivisor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dividend uint64
		divisor  uint64
		wantQuot uint64
		wantRem  uint64
	}{
		{"10/3", 10, 3, 3, 1},
		{"10/2", 10, 2, 5, 0},
		{"0/5", 0, 5, 0, 0},
		{"15/1", 15, 1, 15, 0},
		{"20/5", 20, 5, 4, 0},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := (*impl.Nat)(new(saferith.Nat).SetUint64(tt.dividend))
			b := (*impl.Nat)(new(saferith.Nat).SetUint64(tt.divisor))
			quot := (*impl.Nat)(new(saferith.Nat).SetUint64(888))
			rem := (*impl.Nat)(new(saferith.Nat).SetUint64(999))

			dummy := (*impl.Nat)(new(saferith.Nat))
			ok := dummy.DivModCap(quot, rem, a, b, -1)

			assert.Equal(t, ct.True, ok, "DivModCap ok result")
			assert.Equal(t, tt.wantQuot, quot.Uint64(), "DivModCap quotient")
			assert.Equal(t, tt.wantRem, rem.Uint64(), "DivModCap remainder")
		})
	}
}

func TestNat_BasicOperations(t *testing.T) {
	t.Parallel()

	t.Run("Set", func(t *testing.T) {
		n1 := newNat(42)
		n2 := newNat(0)

		n2.Set(n1)
		assert.Equal(t, n1.String(), n2.String())
		assert.Equal(t, uint64(42), n2.Uint64())
	})

	t.Run("SetZero", func(t *testing.T) {
		n := newNat(12345)
		n.SetZero()

		assert.Equal(t, ct.True, n.IsZero())
		assert.Equal(t, uint64(0), n.Uint64())
		assert.Equal(t, "0x00", n.String()) // SetZero uses a pre-sized constant
	})
}

func TestNat_ArithmeticOperations(t *testing.T) {
	t.Parallel()

	t.Run("Add", func(t *testing.T) {
		testCases := []struct {
			name     string
			a, b     uint64
			expected uint64
		}{
			{"zero_plus_zero", 0, 0, 0},
			{"zero_plus_one", 0, 1, 1},
			{"one_plus_one", 1, 1, 2},
			{"small_numbers", 10, 20, 30},
			{"large_numbers", 1000000, 2000000, 3000000},
			{"max_uint32", 0xFFFFFFFF, 1, 0x100000000},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNat(tc.a)
				b := newNat(tc.b)
				result := newNat(0)

				result.Add(a, b)
				assert.Equal(t, tc.expected, result.Uint64())
			})
		}
	})

	t.Run("AddCap", func(t *testing.T) {
		// cap is bit-capacity, so AddCap(a, b, cap) = (a + b) mod 2^cap
		testCases := []struct {
			name     string
			a, b     uint64
			cap      int
			expected uint64
		}{
			{"simple_add_cap_8", 100, 200, 8, 44},         // (100 + 200) mod 256 = 44
			{"simple_add_cap_16", 30000, 40000, 16, 4464}, // (30000 + 40000) mod 65536 = 4464
			{"overflow_cap_4", 10, 10, 4, 4},              // (10 + 10) mod 16 = 4
			{"no_overflow_cap_10", 100, 200, 10, 300},     // (100 + 200) mod 1024 = 300
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNat(tc.a)
				b := newNat(tc.b)
				result := newNat(0)

				result.AddCap(a, b, tc.cap)
				assert.Equal(t, tc.expected, result.Uint64())
			})
		}
	})

	t.Run("SubCap", func(t *testing.T) {
		testCases := []struct {
			name     string
			a, b     uint64
			expected uint64
		}{
			{"same_numbers", 100, 100, 0},
			{"simple_subtraction", 100, 50, 50},
			{"large_minus_small", 1000000, 1, 999999},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNat(tc.a)
				b := newNat(tc.b)
				result := newNat(0)

				result.SubCap(a, b, -1)
				assert.Equal(t, tc.expected, result.Uint64())
			})
		}
	})

	t.Run("Mul", func(t *testing.T) {
		testCases := []struct {
			name     string
			a, b     uint64
			expected uint64
		}{
			{"zero_times_zero", 0, 0, 0},
			{"zero_times_one", 0, 1, 0},
			{"one_times_one", 1, 1, 1},
			{"simple_multiplication", 7, 6, 42},
			{"large_multiplication", 1000, 1000, 1000000},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNat(tc.a)
				b := newNat(tc.b)
				result := newNat(0)

				result.Mul(a, b)
				assert.Equal(t, tc.expected, result.Uint64())
			})
		}
	})

	t.Run("MulCap", func(t *testing.T) {
		// cap is bit-capacity, so MulCap(a, b, cap) = (a * b) mod 2^cap
		testCases := []struct {
			name     string
			a, b     uint64
			cap      int
			expected uint64
		}{
			{"simple_mul_cap_8", 10, 20, 8, 200},   // (10 * 20) mod 256 = 200
			{"overflow_mul_cap_8", 20, 20, 8, 144}, // (20 * 20) mod 256 = 144
			{"mul_cap_4", 5, 5, 4, 9},              // (5 * 5) mod 16 = 9
			{"mul_cap_16", 300, 300, 16, 24464},    // (300 * 300) mod 65536 = 24464
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNat(tc.a)
				b := newNat(tc.b)
				result := newNat(0)

				result.MulCap(a, b, tc.cap)
				assert.Equal(t, tc.expected, result.Uint64())
			})
		}
	})

	t.Run("Double", func(t *testing.T) {
		testCases := []struct {
			input    uint64
			expected uint64
		}{
			{0, 0},
			{1, 2},
			{100, 200},
			{0xFFFFFFFF, 0x1FFFFFFFE},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
				n := newNat(tc.input)
				result := newNat(0)

				result.Double(n)
				assert.Equal(t, tc.expected, result.Uint64())
			})
		}
	})

	t.Run("Increment", func(t *testing.T) {
		testCases := []struct {
			input    uint64
			expected uint64
		}{
			{0, 1},
			{1, 2},
			{99, 100},
			{0xFFFFFFFF, 0x100000000},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
				n := newNat(tc.input)
				n.Increment()
				assert.Equal(t, tc.expected, n.Uint64())
			})
		}
	})

	t.Run("Decrement", func(t *testing.T) {
		testCases := []struct {
			input    uint64
			expected uint64
		}{
			{1, 0},
			{2, 1},
			{100, 99},
			{0x100000000, 0xFFFFFFFF},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
				n := newNat(tc.input)
				n.Decrement()
				assert.Equal(t, tc.expected, n.Uint64())
			})
		}
	})

	t.Run("DivModCap", func(t *testing.T) {
		testCases := []struct {
			name         string
			a, b         uint64
			cap          int
			expectedQuot uint64
			expectedRem  uint64
		}{
			{"exact_division", 100, 10, -1, 10, 0},
			{"with_remainder", 103, 10, -1, 10, 3},
			{"divide_by_one", 42, 1, -1, 42, 0},
			{"small_numbers", 7, 3, -1, 2, 1},
			{"large_dividend", 1000000, 7, -1, 142857, 1},
			{"equal_numbers", 100, 100, -1, 1, 0},
			{"dividend_smaller", 5, 10, -1, 0, 5},
			{"with_cap_8", 500, 10, 8, 50, 0},
			{"with_cap_16", 65530, 256, 16, 255, 250},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNat(tc.a)
				b := newNat(tc.b)
				quot := newNat(0)
				rem := newNat(0)
				dummy := newNat(0)

				dummy.DivModCap(quot, rem, a, b, tc.cap)
				assert.Equal(t, tc.expectedQuot, quot.Uint64(), "quotient")
				assert.Equal(t, tc.expectedRem, rem.Uint64(), "remainder")

				// Verify the division identity: a = b * quot + rem
				check := newNat(0)
				temp := newNat(0)
				temp.Mul(b, quot)
				check.Add(temp, rem)
				assert.Equal(t, tc.a, check.Uint64(), "division identity check")
			})
		}
	})
}

func TestNat_BitOperations(t *testing.T) {
	t.Parallel()

	t.Run("Bit", func(t *testing.T) {
		// The Bit function returns individual bits like big.Int.Bit
		// Number 170 = 0xAA = 10101010 binary
		n := newNat(170)

		// Test individual bits
		expectedBits := []byte{0, 1, 0, 1, 0, 1, 0, 1}
		for i, expected := range expectedBits {
			actual := n.Bit(uint(i))
			assert.Equal(t, expected, actual, "bit %d", i)
		}

		// Test a larger number: 0x12345 = 74565 = 0b10010001101000101
		n.SetUint64(0x12345)
		// Binary: 1 0010 0011 0100 0101
		//         1  2   3   4   5
		testCases := []struct {
			bit      uint
			expected byte
		}{
			{0, 1}, {1, 0}, {2, 1}, {3, 0}, {4, 0}, // 0101
			{5, 0}, {6, 1}, {7, 0}, {8, 1}, {9, 1}, // 0100 11
			{10, 0}, {11, 0}, {12, 0}, {13, 1}, {14, 0}, {15, 0}, // 00 0100
			{16, 1}, {17, 0}, // 10
		}
		for _, tc := range testCases {
			actual := n.Bit(tc.bit)
			assert.Equal(t, tc.expected, actual, "bit %d of 0x12345", tc.bit)
		}

		// Bits beyond the number should be 0
		assert.Equal(t, byte(0), n.Bit(100))
		assert.Equal(t, byte(0), n.Bit(1000))
	})

	t.Run("Lsh", func(t *testing.T) {
		testCases := []struct {
			name     string
			input    uint64
			shift    uint
			expected uint64
		}{
			{"shift_zero", 1, 0, 1},
			{"shift_one", 1, 1, 2},
			{"shift_multiple", 3, 4, 48},
			{"shift_large", 0xFF, 8, 0xFF00},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				n := newNat(tc.input)
				result := newNat(0)

				result.Lsh(n, tc.shift)
				assert.Equal(t, tc.expected, result.Uint64())
			})
		}
	})

	t.Run("LshCap", func(t *testing.T) {
		// cap specifies the number of bits to produce in the output
		testCases := []struct {
			name     string
			x        uint64
			shift    uint
			cap      int
			expected uint64
		}{
			{"simple_lsh_cap", 3, 4, 8, 48},      // (3 << 4) = 48
			{"lsh_with_cap", 20, 4, 8, 320},      // (20 << 4) = 320
			{"lsh_cap_small", 3, 3, 4, 24},       // (3 << 3) = 24
			{"lsh_cap_large", 100, 8, 16, 25600}, // (100 << 8) = 25600
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				n := newNat(tc.x)
				result := newNat(0)

				result.LshCap(n, tc.shift, tc.cap)
				assert.Equal(t, tc.expected, result.Uint64())
				// Verify the announced length is the cap
				assert.Equal(t, uint(tc.cap), result.AnnouncedLen())
			})
		}
	})

	t.Run("Rsh", func(t *testing.T) {
		testCases := []struct {
			name     string
			input    uint64
			shift    uint
			expected uint64
		}{
			{"shift_zero", 16, 0, 16},
			{"shift_one", 16, 1, 8},
			{"shift_multiple", 48, 4, 3},
			{"shift_large", 0xFF00, 8, 0xFF},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				n := newNat(tc.input)
				result := newNat(0)

				result.Rsh(n, tc.shift)
				assert.Equal(t, tc.expected, result.Uint64())
			})
		}
	})

	t.Run("RshCap", func(t *testing.T) {
		// cap specifies the number of bits to produce in the output
		testCases := []struct {
			name     string
			x        uint64
			shift    uint
			cap      int
			expected uint64
		}{
			{"simple_rsh_cap", 48, 4, 8, 3},     // (48 >> 4) = 3
			{"rsh_cap_small", 255, 4, 4, 15},    // (255 >> 4) = 15
			{"rsh_cap_large", 0x1000, 8, 8, 16}, // (0x1000 >> 8) = 16
			{"rsh_no_overflow", 64, 2, 10, 16},  // (64 >> 2) = 16
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				n := newNat(tc.x)
				result := newNat(0)

				result.RshCap(n, tc.shift, tc.cap)
				assert.Equal(t, tc.expected, result.Uint64())
				// Verify the announced length is the cap
				assert.Equal(t, uint(tc.cap), result.AnnouncedLen())
			})
		}
	})
}

func TestNat_ComparisonOperations(t *testing.T) {
	t.Parallel()

	t.Run("Compare", func(t *testing.T) {
		testCases := []struct {
			name     string
			a, b     uint64
			expectLt bool
			expectEq bool
			expectGt bool
		}{
			{"equal", 10, 10, false, true, false},
			{"less_than", 5, 10, true, false, false},
			{"greater_than", 15, 10, false, false, true},
			{"zero_equal", 0, 0, false, true, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNat(tc.a)
				b := newNat(tc.b)

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
		testCases := []struct {
			a, b     uint64
			expected bool
		}{
			{0, 0, true},
			{1, 1, true},
			{100, 100, true},
			{0, 1, false},
			{100, 101, false},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
				a := newNat(tc.a)
				b := newNat(tc.b)

				result := a.Equal(b)
				if tc.expected {
					assert.Equal(t, ct.True, result)
				} else {
					assert.Equal(t, ct.False, result)
				}
			})
		}
	})

	t.Run("IsZero", func(t *testing.T) {
		zero := newNat(0)
		assert.Equal(t, ct.True, zero.IsZero())

		nonZero := newNat(1)
		assert.Equal(t, ct.False, nonZero.IsZero())

		large := newNat(0xFFFFFFFF)
		assert.Equal(t, ct.False, large.IsZero())
	})

	t.Run("IsNonZero", func(t *testing.T) {
		zero := newNat(0)
		assert.Equal(t, ct.False, zero.IsNonZero())

		nonZero := newNat(1)
		assert.Equal(t, ct.True, nonZero.IsNonZero())

		large := newNat(0xFFFFFFFF)
		assert.Equal(t, ct.True, large.IsNonZero())
	})
}

func TestNat_UtilityOperations(t *testing.T) {
	t.Parallel()

	t.Run("Coprime", func(t *testing.T) {
		testCases := []struct {
			name     string
			a, b     uint64
			expected bool
		}{
			{"coprime_primes", 7, 11, true},
			{"coprime_consecutive", 8, 9, true},
			{"not_coprime_even", 6, 8, false},
			{"not_coprime_multiples", 15, 25, false},
			{"coprime_with_one", 1, 100, true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				a := newNat(tc.a)
				b := newNat(tc.b)

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
		testCases := []struct {
			input    uint64
			expected string
		}{
			{0, "0x00000000_00000000"},
			{1, "0x00000000_00000001"},
			{42, "0x00000000_0000002A"},
			{1000000, "0x00000000_000F4240"},
		}

		for _, tc := range testCases {
			t.Run(tc.expected, func(t *testing.T) {
				n := newNat(tc.input)
				assert.Equal(t, tc.expected, n.String())
			})
		}
	})

	t.Run("TrueLen", func(t *testing.T) {
		// Zero has length 0
		zero := newNat(0)
		assert.Equal(t, uint(0), zero.TrueLen())

		// Small numbers
		small := newNat(255) // fits in 1 limb
		assert.Greater(t, small.TrueLen(), uint(0))

		// Larger numbers
		large := newNat(0xFFFFFFFF)
		assert.Greater(t, large.TrueLen(), uint(0))
	})

	t.Run("AnnouncedLen", func(t *testing.T) {
		n := newNat(42)
		announcedLen := n.AnnouncedLen()
		assert.GreaterOrEqual(t, announcedLen, n.TrueLen())
	})
}

func TestNat_ConditionalOperations(t *testing.T) {
	t.Parallel()

	t.Run("CondAssign", func(t *testing.T) {
		x0 := newNat(100)
		x1 := newNat(200)
		result := newNat(0)

		// Choose x0 (choice = 0)
		result.CondAssign(ct.Choice(0), x0, x1)
		assert.Equal(t, uint64(100), result.Uint64())

		// Choose x1 (choice = 1)
		result.CondAssign(ct.Choice(1), x0, x1)
		assert.Equal(t, uint64(200), result.Uint64())
	})
}

func TestNat_ConversionOperations(t *testing.T) {
	t.Parallel()

	t.Run("Uint64", func(t *testing.T) {
		testCases := []uint64{0, 1, 42, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

		for _, val := range testCases {
			t.Run("", func(t *testing.T) {
				n := newNat(val)
				assert.Equal(t, val, n.Uint64())
			})
		}
	})

	t.Run("SetUint64", func(t *testing.T) {
		n := newNat(0)

		testCases := []uint64{0, 1, 42, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
		for _, val := range testCases {
			n.SetUint64(val)
			assert.Equal(t, val, n.Uint64())
		}
	})

	t.Run("Bytes", func(t *testing.T) {
		testCases := []uint64{0, 0xFF, 0x1234, 0xDEADBEEF}

		for _, input := range testCases {
			t.Run("", func(t *testing.T) {
				n := newNat(input)
				result := n.Bytes()

				// Verify round-trip conversion
				n2 := newNat(0)
				n2.SetBytes(result)
				assert.Equal(t, input, n2.Uint64())
			})
		}
	})

	t.Run("SetBytes", func(t *testing.T) {
		testCases := []struct {
			input    []byte
			expected uint64
		}{
			{[]byte{}, 0},
			{[]byte{0xFF}, 0xFF},
			{[]byte{0x12, 0x34}, 0x1234},
			{[]byte{0xDE, 0xAD, 0xBE, 0xEF}, 0xDEADBEEF},
		}

		for _, tc := range testCases {
			t.Run("", func(t *testing.T) {
				n := newNat(0)
				ok := n.SetBytes(tc.input)

				assert.Equal(t, ct.True, ok)
				assert.Equal(t, tc.expected, n.Uint64())
			})
		}
	})

	t.Run("Bytes_SetBytes_Roundtrip", func(t *testing.T) {
		testValues := []uint64{0, 1, 255, 0x1234, 0xDEADBEEF, 0xFFFFFFFFFFFFFFFF}

		for _, val := range testValues {
			t.Run("", func(t *testing.T) {
				original := newNat(val)
				bytes := original.Bytes()

				recovered := newNat(0)
				ok := recovered.SetBytes(bytes)

				assert.Equal(t, ct.True, ok)
				assert.Equal(t, original.Uint64(), recovered.Uint64())
			})
		}
	})
}

func TestNat_CapacityOperations(t *testing.T) {
	t.Parallel()

	t.Run("Resize", func(t *testing.T) {
		n := newNat(42)

		// Resize changes the announced capacity of the number
		n.Resize(10)
		assert.Equal(t, uint(10), n.AnnouncedLen())

		// When resizing to smaller than needed, value gets truncated
		// 42 = 0b101010 needs 6 bits, so resizing to 5 bits truncates to 0b01010 = 10
		n.SetUint64(42)
		n.Resize(5)
		assert.Equal(t, uint(5), n.AnnouncedLen())
		assert.Equal(t, uint64(10), n.Uint64()) // 42 mod 32 (2^5) = 10

		// Resize to larger preserves value
		n.SetUint64(100)
		n.Resize(64)
		assert.Equal(t, uint(64), n.AnnouncedLen())
		assert.Equal(t, uint64(100), n.Uint64())
	})
}

func TestNat_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("Operations_With_Zero", func(t *testing.T) {
		zero := newNat(0)
		nonZero := newNat(42)
		result := newNat(0)

		// Add with zero
		result.Add(zero, nonZero)
		assert.Equal(t, uint64(42), result.Uint64())

		result.Add(nonZero, zero)
		assert.Equal(t, uint64(42), result.Uint64())

		// Multiply with zero
		result.Mul(zero, nonZero)
		assert.Equal(t, uint64(0), result.Uint64())

		result.Mul(nonZero, zero)
		assert.Equal(t, uint64(0), result.Uint64())

		// Subtract zero
		result.SubCap(nonZero, zero, -1)
		assert.Equal(t, uint64(42), result.Uint64())
	})

	t.Run("Self_Assignment", func(t *testing.T) {
		n := newNat(42)

		// Self add
		n.Add(n, n)
		assert.Equal(t, uint64(84), n.Uint64())

		// Self multiply
		n.SetUint64(7)
		n.Mul(n, n)
		assert.Equal(t, uint64(49), n.Uint64())

		// Self set
		n.SetUint64(42)
		n.Set(n)
		assert.Equal(t, uint64(42), n.Uint64())
	})

	t.Run("Large_Numbers", func(t *testing.T) {
		// Test with numbers larger than uint64
		// Use little-endian format for large numbers
		largeBytes := []byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}

		n1 := newNatFromBytes(largeBytes)
		n2 := newNatFromBytes(largeBytes)
		result := newNat(0)

		// Addition should work
		result.Add(n1, n2)
		assert.NotEmpty(t, result.String())

		// Comparison should work
		eq := n1.Equal(n2)
		assert.Equal(t, ct.True, eq)

		// Bytes conversion should work
		recoveredBytes := n1.Bytes()
		assert.True(t, bytes.Equal(largeBytes, recoveredBytes))
	})
}

func TestNat_ConstantTime(t *testing.T) {
	t.Parallel()

	t.Run("Comparison_Constant_Time", func(t *testing.T) {
		// This test verifies that comparison operations return ct.Bool
		// which ensures constant-time execution
		n1 := newNat(42)
		n2 := newNat(43)

		// These operations should return ct.Bool types
		var ltResult ct.Bool
		var eqResult ct.Bool
		var gtResult ct.Bool

		ltResult, eqResult, gtResult = n1.Compare(n2)
		assert.Equal(t, ct.True, ltResult)
		assert.Equal(t, ct.False, eqResult)
		assert.Equal(t, ct.False, gtResult)

		// Equal operation returns ct.Bool
		var equalResult ct.Bool = n1.Equal(n2)
		assert.Equal(t, ct.False, equalResult)

		// IsZero returns ct.Bool
		var zeroResult ct.Bool = n1.IsZero()
		assert.Equal(t, ct.False, zeroResult)

		// IsNonZero returns ct.Bool
		var nonZeroResult ct.Bool = n1.IsNonZero()
		assert.Equal(t, ct.True, nonZeroResult)

		// Coprime returns ct.Bool
		var coprimeResult ct.Bool = n1.Coprime(n2)
		assert.Equal(t, ct.True, coprimeResult)
	})
}

func BenchmarkNat_Add(b *testing.B) {
	n1 := newNat(0xFFFFFFFF)
	n2 := newNat(0xFFFFFFFF)
	result := newNat(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Add(n1, n2)
	}
}

func BenchmarkNat_Mul(b *testing.B) {
	n1 := newNat(0xFFFF)
	n2 := newNat(0xFFFF)
	result := newNat(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Mul(n1, n2)
	}
}

func BenchmarkNat_Compare(b *testing.B) {
	n1 := newNat(0xFFFFFFFF)
	n2 := newNat(0xFFFFFFFE)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = n1.Compare(n2)
	}
}

// TestNat_SaferithCompatibility ensures that our Nat type
// correctly wraps saferith.Nat functionality
func TestNat_SaferithCompatibility(t *testing.T) {
	t.Parallel()

	t.Run("Type_Conversion", func(t *testing.T) {
		// Verify that Nat can be converted to/from saferith.Nat
		saferithNat := new(saferith.Nat).SetUint64(42)
		implNat := (*impl.Nat)(saferithNat)

		assert.Equal(t, uint64(42), implNat.Uint64())
		assert.Equal(t, "0x00000000_0000002A", implNat.String())

		// Convert back
		backToSaferith := (*saferith.Nat)(implNat)
		assert.Equal(t, uint64(42), backToSaferith.Uint64())
	})
}

// TestNat_InterfaceCompliance verifies that Nat implements
// the required internal.NatMutable interface
func TestNat_InterfaceCompliance(t *testing.T) {
	t.Parallel()

	// This test passes if the code compiles, as the interface
	// compliance is checked at compile time in nat.go:14
	require.NotNil(t, newNat(0))
}
