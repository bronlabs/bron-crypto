package ct_test

import (
	"math"
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestIsZero_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random integer value
		value := rapid.Int().Draw(t, "value")
		// Check if IsZero returns One for zero and Zero otherwise
		drewZero := value == 0
		actual := ct.IsZero(value) == ct.True
		require.Equal(t, drewZero, actual)
	})
}

// TestIsZero tests the IsZero function for various integer types
func TestIsZero(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		value    any
		expected ct.Choice
	}{
		// Unsigned types
		{"uint8(0)", uint8(0), ct.One},
		{"uint8(1)", uint8(1), ct.Zero},
		{"uint8(255)", uint8(255), ct.Zero},
		{"uint16(0)", uint16(0), ct.One},
		{"uint16(65535)", uint16(65535), ct.Zero},
		{"uint32(0)", uint32(0), ct.One},
		{"uint32(max)", uint32(math.MaxUint32), ct.Zero},
		{"uint64(0)", uint64(0), ct.One},
		{"uint64(max)", uint64(math.MaxUint64), ct.Zero},

		// Signed types
		{"int8(0)", int8(0), ct.One},
		{"int8(-1)", int8(-1), ct.Zero},
		{"int8(127)", int8(127), ct.Zero},
		{"int8(-128)", int8(-128), ct.Zero},
		{"int16(0)", int16(0), ct.One},
		{"int16(-1)", int16(-1), ct.Zero},
		{"int32(0)", int32(0), ct.One},
		{"int32(min)", int32(math.MinInt32), ct.Zero},
		{"int32(max)", int32(math.MaxInt32), ct.Zero},
		{"int64(0)", int64(0), ct.One},
		{"int64(min)", int64(math.MinInt64), ct.Zero},
		{"int64(max)", int64(math.MaxInt64), ct.Zero},

		// Regular int/uint
		{"int(0)", int(0), ct.One},
		{"int(-1)", int(-1), ct.Zero},
		{"uint(0)", uint(0), ct.One},
		{"uint(1)", uint(1), ct.Zero},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var result ct.Choice
			switch v := tt.value.(type) {
			case uint8:
				result = ct.IsZero(v)
			case uint16:
				result = ct.IsZero(v)
			case uint32:
				result = ct.IsZero(v)
			case uint64:
				result = ct.IsZero(v)
			case int8:
				result = ct.IsZero(v)
			case int16:
				result = ct.IsZero(v)
			case int32:
				result = ct.IsZero(v)
			case int64:
				result = ct.IsZero(v)
			case int:
				result = ct.IsZero(v)
			case uint:
				result = ct.IsZero(v)
			default:
				t.Fatalf("unsupported type %T", v)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEqual_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if Equal returns One for equal values and Zero otherwise
		expected := x == y
		actual := ct.Equal(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

// TestEqual tests the Equal function
func TestEqual(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		x, y     any
		expected ct.Choice
	}{
		// Equal values
		{"uint8 equal", uint8(42), uint8(42), ct.One},
		{"int8 equal", int8(-42), int8(-42), ct.One},
		{"uint64 equal", uint64(math.MaxUint64), uint64(math.MaxUint64), ct.One},
		{"int64 equal", int64(math.MinInt64), int64(math.MinInt64), ct.One},

		// Unequal values
		{"uint8 unequal", uint8(42), uint8(43), ct.Zero},
		{"int8 unequal", int8(-42), int8(42), ct.Zero},
		{"uint64 unequal", uint64(0), uint64(1), ct.Zero},
		{"int64 unequal", int64(-1), int64(1), ct.Zero},

		// Boundary cases
		{"uint8 0 vs max", uint8(0), uint8(255), ct.Zero},
		{"int8 min vs max", int8(-128), int8(127), ct.Zero},
		{"uint64 0 vs max", uint64(0), uint64(math.MaxUint64), ct.Zero},
		{"int64 min vs max", int64(math.MinInt64), int64(math.MaxInt64), ct.Zero},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var result ct.Choice
			switch x := tt.x.(type) {
			case uint8:
				result = ct.Equal(x, tt.y.(uint8))
			case int8:
				result = ct.Equal(x, tt.y.(int8))
			case uint64:
				result = ct.Equal(x, tt.y.(uint64))
			case int64:
				result = ct.Equal(x, tt.y.(int64))
			default:
				t.Fatalf("unsupported type %T", x)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGreater_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if Greater returns One for x > y and Zero otherwise
		expected := x > y
		actual := ct.Greater(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestLess_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if Less returns One for x < y and Zero otherwise
		expected := x < y
		actual := ct.Less(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestLessOrEqual_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if LessOrEqual returns One for x <= y and Zero otherwise
		expected := x <= y
		actual := ct.LessOrEqual(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestGreaterOrEqual_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if GreaterOrEqual returns One for x >= y and Zero otherwise
		expected := x >= y
		actual := ct.GreaterOrEqual(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestCompareInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		agt, aeq, alt := ct.CompareInt(x, y)
		if x > y {
			require.Equal(t, ct.True, agt)
		} else if x == y {
			require.Equal(t, ct.True, aeq)
		} else {
			require.Equal(t, ct.True, alt)
		}
	})
}

// TestCompareInt tests the CompareInt function
func TestCompareInt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		x, y       int64
		gt, eq, lt ct.Bool
	}{
		{"equal", 42, 42, ct.False, ct.True, ct.False},
		{"x > y", 100, 50, ct.True, ct.False, ct.False},
		{"x < y", 50, 100, ct.False, ct.False, ct.True},
		{"negative equal", -42, -42, ct.False, ct.True, ct.False},
		{"negative x > y", -50, -100, ct.True, ct.False, ct.False},
		{"negative x < y", -100, -50, ct.False, ct.False, ct.True},
		{"min vs max", math.MinInt64, math.MaxInt64, ct.False, ct.False, ct.True},
		{"max vs min", math.MaxInt64, math.MinInt64, ct.True, ct.False, ct.False},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gt, eq, lt := ct.CompareInt(tt.x, tt.y)
			assert.Equal(t, tt.gt, gt, "gt")
			assert.Equal(t, tt.eq, eq, "eq")
			assert.Equal(t, tt.lt, lt, "lt")
		})
	}
}

func TestCSelectInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random choice and two integer values
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))
		x0 := rapid.Int().Draw(t, "x0")
		x1 := rapid.Int().Draw(t, "x1")
		// Check if CSelectInt returns x0 when choice is 0 and x1 when choice is 1
		expected := x0
		if choice == ct.True {
			expected = x1
		}
		actual := ct.CSelectInt(choice, x0, x1)
		require.Equal(t, expected, actual)
	})
}

// TestCSelectInt tests the SelectInteger function for integers
func TestCSelectInt(t *testing.T) {
	t.Parallel()
	// Test with various integer types
	t.Run("uint8", func(t *testing.T) {
		t.Parallel()
		var a, b uint8 = 42, 100
		assert.Equal(t, a, ct.CSelectInt(ct.Zero, a, b))
		assert.Equal(t, b, ct.CSelectInt(ct.One, a, b))
	})

	t.Run("int64", func(t *testing.T) {
		t.Parallel()
		var a, b int64 = -42, 100
		assert.Equal(t, a, ct.CSelectInt(ct.Zero, a, b))
		assert.Equal(t, b, ct.CSelectInt(ct.One, a, b))
	})

	t.Run("boundary", func(t *testing.T) {
		t.Parallel()
		// Test with boundary values
		var a, b int64 = math.MinInt64, math.MaxInt64
		assert.Equal(t, a, ct.CSelectInt(ct.Zero, a, b))
		assert.Equal(t, b, ct.CSelectInt(ct.One, a, b))
	})
}

func TestCMOVInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))
		src := rapid.Int().Draw(t, "src")

		var expected int
		if choice == ct.True {
			expected = src
		}
		var actual int
		ct.CMOVInt(&actual, choice, &src)
		require.Equal(t, expected, actual)
	})
}

// TestCMOVInt tests the conditional move for integers
func TestCMOVInt(t *testing.T) {
	t.Parallel()

	t.Run("uint64", func(t *testing.T) {
		t.Parallel()

		// Test move when yes=1
		dst := uint64(100)
		src := uint64(200)
		ct.CMOVInt(&dst, ct.One, &src)
		assert.Equal(t, uint64(200), dst, "dst should be updated when yes=1")

		// Test no move when yes=0
		dst = uint64(100)
		src = uint64(200)
		ct.CMOVInt(&dst, ct.Zero, &src)
		assert.Equal(t, uint64(100), dst, "dst should be unchanged when yes=0")
	})

	t.Run("int64", func(t *testing.T) {
		t.Parallel()

		// Test with negative values
		dst := int64(-100)
		src := int64(200)
		ct.CMOVInt(&dst, ct.One, &src)
		assert.Equal(t, int64(200), dst, "dst should be updated when yes=1")

		// Test no move
		dst = int64(-100)
		src = int64(200)
		ct.CMOVInt(&dst, ct.Zero, &src)
		assert.Equal(t, int64(-100), dst, "dst should be unchanged when yes=0")
	})

	t.Run("boundary values", func(t *testing.T) {
		t.Parallel()

		dst := uint64(0)
		src := uint64(math.MaxUint64)
		ct.CMOVInt(&dst, ct.One, &src)
		assert.Equal(t, uint64(math.MaxUint64), dst)

		dst = uint64(math.MaxUint64)
		src = uint64(0)
		ct.CMOVInt(&dst, ct.Zero, &src)
		assert.Equal(t, uint64(math.MaxUint64), dst)
	})

	t.Run("alias safety", func(t *testing.T) {
		t.Parallel()

		// Test that it works when dst == src (same pointer)
		val := uint64(100)
		ct.CMOVInt(&val, ct.One, &val)
		assert.Equal(t, uint64(100), val, "should work when dst and src are same")
	})
}

func TestCSwapInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		var expectedX, expectedY int
		if choice == ct.True {
			expectedX = y
			expectedY = x
		} else {
			expectedX = x
			expectedY = y
		}
		var actualX, actualY int = x, y
		ct.CSwapInt(&actualX, &actualY, choice)
		require.Equal(t, expectedX, actualX)
		require.Equal(t, expectedY, actualY)
	})
}

// TestCSwapInt tests the conditional swap for integers
func TestCSwapInt(t *testing.T) {
	t.Parallel()

	t.Run("uint64 swap", func(t *testing.T) {
		t.Parallel()

		// Test swap when yes=1
		x := uint64(100)
		y := uint64(200)
		ct.CSwapInt(&x, &y, ct.One)
		assert.Equal(t, uint64(200), x, "x should be swapped when yes=1")
		assert.Equal(t, uint64(100), y, "y should be swapped when yes=1")

		// Test no swap when yes=0
		x = uint64(100)
		y = uint64(200)
		ct.CSwapInt(&x, &y, ct.Zero)
		assert.Equal(t, uint64(100), x, "x should be unchanged when yes=0")
		assert.Equal(t, uint64(200), y, "y should be unchanged when yes=0")
	})

	t.Run("int64 swap", func(t *testing.T) {
		t.Parallel()

		// Test with negative values
		x := int64(-100)
		y := int64(200)
		ct.CSwapInt(&x, &y, ct.One)
		assert.Equal(t, int64(200), x, "x should be swapped")
		assert.Equal(t, int64(-100), y, "y should be swapped")
	})

	t.Run("boundary values", func(t *testing.T) {
		t.Parallel()

		x := uint64(0)
		y := uint64(math.MaxUint64)
		ct.CSwapInt(&x, &y, ct.One)
		assert.Equal(t, uint64(math.MaxUint64), x)
		assert.Equal(t, uint64(0), y)
	})

	t.Run("same values", func(t *testing.T) {
		t.Parallel()

		x := uint64(42)
		y := uint64(42)
		ct.CSwapInt(&x, &y, ct.One)
		assert.Equal(t, uint64(42), x, "swapping same values should work")
		assert.Equal(t, uint64(42), y)
	})

	t.Run("alias safety", func(t *testing.T) {
		t.Parallel()

		// Test that it works when x == y (same pointer)
		val := uint64(100)
		ct.CSwapInt(&val, &val, ct.One)
		assert.Equal(t, uint64(100), val, "should work when x and y are same pointer")
	})
}

func TestMin_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.Int().Draw(t, "a")
		b := rapid.Int().Draw(t, "b")
		expected := min(a, b)
		actual := ct.Min(a, b)
		require.Equal(t, expected, actual)
	})
}

func TestMax_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.Int().Draw(t, "a")
		b := rapid.Int().Draw(t, "b")
		expected := max(a, b)
		actual := ct.Max(a, b)
		require.Equal(t, expected, actual)
	})
}

// TestMinMax tests the Min and Max functions
func TestMinMax(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		a, b     int64
		min, max int64
	}{
		{"a < b", 10, 20, 10, 20},
		{"a > b", 20, 10, 10, 20},
		{"a == b", 15, 15, 15, 15},
		{"negative", -10, 10, -10, 10},
		{"both negative", -20, -10, -20, -10},
		{"min/max int64", math.MinInt64, math.MaxInt64, math.MinInt64, math.MaxInt64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.min, ct.Min(tt.a, tt.b), "Min(%d, %d)", tt.a, tt.b)
			assert.Equal(t, tt.max, ct.Max(tt.a, tt.b), "Max(%d, %d)", tt.a, tt.b)
		})
	}
}

func TestIsqrt64_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.Uint64().Draw(t, "n")
		nBig := new(big.Int).SetUint64(n)
		expectedBig := new(big.Int).Sqrt(nBig)
		expected := expectedBig.Uint64()
		actual := ct.Isqrt64(n)
		require.Equal(t, expected, actual)
	})
}

// TestIsqrt64 tests the constant-time integer square root
func TestIsqrt64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n        uint64
		expected uint64
	}{
		{0, 0},
		{1, 1},
		{2, 1},
		{3, 1},
		{4, 2},
		{8, 2},
		{9, 3},
		{15, 3},
		{16, 4},
		{100, 10},
		{1000, 31},
		{10000, 100},
		{1 << 20, 1 << 10},
		{1 << 32, 1 << 16},
		{1 << 40, 1 << 20},
		{math.MaxUint64, 4294967295}, // floor(sqrt(2^64-1))
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, ct.Isqrt64(tt.n), "Isqrt64(%d)", tt.n)
		})
	}
}

func TestLessU64_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := rapid.Uint64().Draw(t, "x")
		y := rapid.Uint64().Draw(t, "y")
		expected := x < y
		actual := ct.LessU64(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

// TestLessU64 tests unsigned 64-bit comparison
func TestLessU64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		x, y     uint64
		expected ct.Choice
	}{
		{0, 0, ct.Zero},
		{0, 1, ct.One},
		{1, 0, ct.Zero},
		{100, 200, ct.One},
		{200, 100, ct.Zero},
		{math.MaxUint64, math.MaxUint64, ct.Zero},
		{0, math.MaxUint64, ct.One},
		{math.MaxUint64, 0, ct.Zero},
		{math.MaxUint64 - 1, math.MaxUint64, ct.One},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, ct.LessU64(tt.x, tt.y), "LessU64(%d, %d)", tt.x, tt.y)
		})
	}
}

func TestLessI64_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := rapid.Int64().Draw(t, "x")
		y := rapid.Int64().Draw(t, "y")
		expected := x < y
		actual := ct.LessI64(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

// TestLessI64 tests signed 64-bit comparison
func TestLessI64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		x, y     int64
		expected ct.Choice
	}{
		{0, 0, ct.Zero},
		{0, 1, ct.One},
		{1, 0, ct.Zero},
		{-1, 0, ct.One},
		{0, -1, ct.Zero},
		{-100, -50, ct.One},
		{-50, -100, ct.Zero},
		{math.MinInt64, math.MaxInt64, ct.One},
		{math.MaxInt64, math.MinInt64, ct.Zero},
		{math.MinInt64, math.MinInt64, ct.Zero},
		{math.MaxInt64, math.MaxInt64, ct.Zero},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, ct.LessI64(tt.x, tt.y), "LessI64(%d, %d)", tt.x, tt.y)
		})
	}
}
