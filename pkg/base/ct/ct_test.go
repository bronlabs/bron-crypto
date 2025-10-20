package ct_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// TestChoice tests the Choice/Bool type and its Not() method
func TestChoice(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		choice   ct.Choice
		expected ct.Choice
	}{
		{"Not(0)", ct.Zero, ct.One},
		{"Not(1)", ct.One, ct.Zero},
		{"Not(False)", ct.False, ct.True},
		{"Not(True)", ct.True, ct.False},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.choice.Not())
		})
	}
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

// TestComparison tests Greater, Less, GreaterOrEqual, LessOrEqual
func TestComparison(t *testing.T) {
	t.Parallel()
	// Test unsigned comparisons
	t.Run("unsigned", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			x, y             uint64
			gt, lt, gte, lte ct.Choice
		}{
			{0, 0, ct.Zero, ct.Zero, ct.One, ct.One},
			{1, 0, ct.One, ct.Zero, ct.One, ct.Zero},
			{0, 1, ct.Zero, ct.One, ct.Zero, ct.One},
			{100, 50, ct.One, ct.Zero, ct.One, ct.Zero},
			{50, 100, ct.Zero, ct.One, ct.Zero, ct.One},
			{math.MaxUint64, 0, ct.One, ct.Zero, ct.One, ct.Zero},
			{0, math.MaxUint64, ct.Zero, ct.One, ct.Zero, ct.One},
			{math.MaxUint64, math.MaxUint64, ct.Zero, ct.Zero, ct.One, ct.One},
		}

		for _, tt := range tests {
			assert.Equal(t, tt.gt, ct.Greater(tt.x, tt.y), "Greater(%d, %d)", tt.x, tt.y)
			assert.Equal(t, tt.lt, ct.Less(tt.x, tt.y), "Less(%d, %d)", tt.x, tt.y)
			assert.Equal(t, tt.gte, ct.GreaterOrEqual(tt.x, tt.y), "GreaterOrEqual(%d, %d)", tt.x, tt.y)
			assert.Equal(t, tt.lte, ct.LessOrEqual(tt.x, tt.y), "LessOrEqual(%d, %d)", tt.x, tt.y)
		}
	})

	// Test signed comparisons
	t.Run("signed", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			x, y             int64
			gt, lt, gte, lte ct.Choice
		}{
			{0, 0, ct.Zero, ct.Zero, ct.One, ct.One},
			{1, 0, ct.One, ct.Zero, ct.One, ct.Zero},
			{0, 1, ct.Zero, ct.One, ct.Zero, ct.One},
			{-1, 0, ct.Zero, ct.One, ct.Zero, ct.One},
			{0, -1, ct.One, ct.Zero, ct.One, ct.Zero},
			{-1, -1, ct.Zero, ct.Zero, ct.One, ct.One},
			{-100, -50, ct.Zero, ct.One, ct.Zero, ct.One},
			{-50, -100, ct.One, ct.Zero, ct.One, ct.Zero},
			{math.MinInt64, math.MaxInt64, ct.Zero, ct.One, ct.Zero, ct.One},
			{math.MaxInt64, math.MinInt64, ct.One, ct.Zero, ct.One, ct.Zero},
			{math.MinInt64, math.MinInt64, ct.Zero, ct.Zero, ct.One, ct.One},
			{math.MaxInt64, math.MaxInt64, ct.Zero, ct.Zero, ct.One, ct.One},
		}

		for _, tt := range tests {
			assert.Equal(t, tt.gt, ct.Greater(tt.x, tt.y), "Greater(%d, %d)", tt.x, tt.y)
			assert.Equal(t, tt.lt, ct.Less(tt.x, tt.y), "Less(%d, %d)", tt.x, tt.y)
			assert.Equal(t, tt.gte, ct.GreaterOrEqual(tt.x, tt.y), "GreaterOrEqual(%d, %d)", tt.x, tt.y)
			assert.Equal(t, tt.lte, ct.LessOrEqual(tt.x, tt.y), "LessOrEqual(%d, %d)", tt.x, tt.y)
		}
	})
}

// TestCmp tests the Cmp function
func TestCmp(t *testing.T) {
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
			gt, eq, lt := ct.CompareInteger(tt.x, tt.y)
			assert.Equal(t, tt.gt, gt, "gt")
			assert.Equal(t, tt.eq, eq, "eq")
			assert.Equal(t, tt.lt, lt, "lt")
		})
	}
}

// TestSelectInteger tests the SelectInteger function for integers
func TestSelectInteger(t *testing.T) {
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

// TestSliceEachEqual tests the SliceEachEqual function
func TestSliceEachEqual(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		s        []uint8
		e        uint8
		expected ct.Choice
	}{
		{"all equal", []uint8{5, 5, 5, 5}, 5, ct.One},
		{"one different", []uint8{5, 5, 3, 5}, 5, ct.Zero},
		{"all different", []uint8{1, 2, 3, 4}, 5, ct.Zero},
		{"empty slice", []uint8{}, 5, ct.One},
		{"single element equal", []uint8{5}, 5, ct.One},
		{"single element different", []uint8{3}, 5, ct.Zero},
		{"all zeros", []uint8{0, 0, 0}, 0, ct.One},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, ct.SliceEachEqual(tt.s, tt.e))
		})
	}
}

// TestSliceEqual tests the SliceEqual function
func TestSliceEqual(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		x, y     []uint8
		expected ct.Choice
	}{
		{"equal slices", []uint8{1, 2, 3}, []uint8{1, 2, 3}, ct.One},
		{"different slices", []uint8{1, 2, 3}, []uint8{1, 2, 4}, ct.Zero},
		{"empty slices", []uint8{}, []uint8{}, ct.One},
		{"single element equal", []uint8{5}, []uint8{5}, ct.One},
		{"single element different", []uint8{5}, []uint8{3}, ct.Zero},
		{"all zeros", []uint8{0, 0, 0}, []uint8{0, 0, 0}, ct.One},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, ct.SliceEqual(tt.x, tt.y))
		})
	}

	t.Run("panic on different lengths", func(t *testing.T) {
		t.Parallel()
		assert.Panics(t, func() {
			ct.SliceEqual([]uint8{1, 2}, []uint8{1, 2, 3})
		})
	})
}

// TestSliceIsZero tests the SliceIsZero function
func TestSliceIsZero(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		s        []uint8
		expected ct.Choice
	}{
		{"all zeros", []uint8{0, 0, 0, 0}, ct.One},
		{"one non-zero", []uint8{0, 0, 1, 0}, ct.Zero},
		{"all non-zero", []uint8{1, 2, 3, 4}, ct.Zero},
		{"empty slice", []uint8{}, ct.One},
		{"single zero", []uint8{0}, ct.One},
		{"single non-zero", []uint8{5}, ct.Zero},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, ct.SliceIsZero(tt.s))
		})
	}
}

// TestBytesCompare tests the BytesCompare function
func TestBytesCompare(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		x, y       []byte
		lt, eq, gt ct.Bool
	}{
		{"equal", []byte{1, 2, 3}, []byte{1, 2, 3}, ct.False, ct.True, ct.False},
		{"x < y first byte", []byte{1, 2, 3}, []byte{2, 2, 3}, ct.True, ct.False, ct.False},
		{"x > y first byte", []byte{2, 2, 3}, []byte{1, 2, 3}, ct.False, ct.False, ct.True},
		{"x < y middle byte", []byte{1, 2, 3}, []byte{1, 3, 3}, ct.True, ct.False, ct.False},
		{"x > y middle byte", []byte{1, 3, 3}, []byte{1, 2, 3}, ct.False, ct.False, ct.True},
		{"x < y last byte", []byte{1, 2, 3}, []byte{1, 2, 4}, ct.True, ct.False, ct.False},
		{"x > y last byte", []byte{1, 2, 4}, []byte{1, 2, 3}, ct.False, ct.False, ct.True},
		{"x prefix of y", []byte{1, 2}, []byte{1, 2, 3}, ct.True, ct.False, ct.False},
		{"y prefix of x", []byte{1, 2, 3}, []byte{1, 2}, ct.False, ct.False, ct.True},
		{"empty vs non-empty", []byte{}, []byte{1}, ct.True, ct.False, ct.False},
		{"non-empty vs empty", []byte{1}, []byte{}, ct.False, ct.False, ct.True},
		{"both empty", []byte{}, []byte{}, ct.False, ct.True, ct.False},
		{"lexicographic", []byte{1, 255}, []byte{2, 0}, ct.True, ct.False, ct.False},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lt, eq, gt := ct.CompareBytes(tt.x, tt.y)
			assert.Equal(t, tt.lt, lt, "lt")
			assert.Equal(t, tt.eq, eq, "eq")
			assert.Equal(t, tt.gt, gt, "gt")
		})
	}
}

// TestConstantTime is a basic smoke test for constant-time properties
func TestConstantTime(t *testing.T) {
	t.Parallel()
	// This is a basic smoke test - true constant-time verification requires
	// specialised tools like dudect or manual assembly inspection

	// Test that SelectInteger returns consistent results
	t.Run("SelectInteger consistency", func(t *testing.T) {
		t.Parallel()
		for i := range 1000 {
			a, b := uint64(i), uint64(i+1000)
			assert.Equal(t, a, ct.CSelectInt(ct.Zero, a, b))
			assert.Equal(t, b, ct.CSelectInt(ct.One, a, b))
		}
	})

	// Test that comparisons are consistent
	t.Run("Comparison consistency", func(t *testing.T) {
		t.Parallel()
		for i := int64(-500); i < 500; i++ {
			for j := int64(-500); j < 500; j++ {
				gt := ct.Greater(i, j)
				lt := ct.Less(i, j)
				eq := ct.Equal(i, j)

				// Exactly one should be true (or none if not equal)
				sum := int(gt) + int(lt) + int(eq)
				require.LessOrEqual(t, sum, 1, "Inconsistent comparison for %d, %d", i, j)

				// If equal, neither gt nor lt should be true
				if eq == ct.One {
					assert.Equal(t, ct.Zero, gt, "Equal but also gt for %d, %d", i, j)
					assert.Equal(t, ct.Zero, lt, "Equal but also lt for %d, %d", i, j)
				}
			}
		}
	})
}

// TestAndBytes tests the AndBytes function
func TestAndBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		x, y     []byte
		expected []byte
		n        int
	}{
		{
			name:     "simple AND",
			x:        []byte{0xFF, 0x0F, 0xAA},
			y:        []byte{0x0F, 0xFF, 0x55},
			expected: []byte{0x0F, 0x0F, 0x00},
			n:        3,
		},
		{
			name:     "all zeros",
			x:        []byte{0x00, 0x00, 0x00},
			y:        []byte{0xFF, 0xFF, 0xFF},
			expected: []byte{0x00, 0x00, 0x00},
			n:        3,
		},
		{
			name:     "all ones",
			x:        []byte{0xFF, 0xFF, 0xFF},
			y:        []byte{0xFF, 0xFF, 0xFF},
			expected: []byte{0xFF, 0xFF, 0xFF},
			n:        3,
		},
		{
			name:     "different lengths - x longer",
			x:        []byte{0xFF, 0xFF, 0xFF, 0xFF},
			y:        []byte{0x0F, 0x0F},
			expected: []byte{0x0F, 0x0F},
			n:        2,
		},
		{
			name:     "different lengths - y longer",
			x:        []byte{0xAA, 0xBB},
			y:        []byte{0x55, 0x44, 0x33, 0x22},
			expected: []byte{0x00, 0x00},
			n:        2,
		},
		{
			name:     "empty x",
			x:        []byte{},
			y:        []byte{0xFF, 0xFF},
			expected: []byte{},
			n:        0,
		},
		{
			name:     "empty y",
			x:        []byte{0xFF, 0xFF},
			y:        []byte{},
			expected: []byte{},
			n:        0,
		},
		{
			name:     "both empty",
			x:        []byte{},
			y:        []byte{},
			expected: []byte{},
			n:        0,
		},
		{
			name:     "single byte",
			x:        []byte{0xF0},
			y:        []byte{0x0F},
			expected: []byte{0x00},
			n:        1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dst := make([]byte, len(tt.expected))
			n := ct.AndBytes(dst, tt.x, tt.y)
			assert.Equal(t, tt.n, n, "returned length should match")
			assert.Equal(t, tt.expected, dst, "AND result should match")
		})
	}

	// Test panic on short dst
	t.Run("panic on short dst", func(t *testing.T) {
		t.Parallel()
		x := []byte{0xFF, 0xFF, 0xFF}
		y := []byte{0x00, 0x00, 0x00}
		dst := make([]byte, 2) // Too short
		assert.Panics(t, func() {
			ct.AndBytes(dst, x, y)
		}, "should panic when dst is too short")
	})
}

// TestOrBytes tests the OrBytes function
func TestOrBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		x, y     []byte
		expected []byte
		n        int
	}{
		{
			name:     "simple OR",
			x:        []byte{0xF0, 0x0F, 0xAA},
			y:        []byte{0x0F, 0xF0, 0x55},
			expected: []byte{0xFF, 0xFF, 0xFF},
			n:        3,
		},
		{
			name:     "all zeros",
			x:        []byte{0x00, 0x00, 0x00},
			y:        []byte{0x00, 0x00, 0x00},
			expected: []byte{0x00, 0x00, 0x00},
			n:        3,
		},
		{
			name:     "all ones",
			x:        []byte{0xFF, 0xFF, 0xFF},
			y:        []byte{0xFF, 0xFF, 0xFF},
			expected: []byte{0xFF, 0xFF, 0xFF},
			n:        3,
		},
		{
			name:     "zeros with ones",
			x:        []byte{0x00, 0x00, 0x00},
			y:        []byte{0xFF, 0xFF, 0xFF},
			expected: []byte{0xFF, 0xFF, 0xFF},
			n:        3,
		},
		{
			name:     "different lengths - x longer",
			x:        []byte{0xAA, 0xBB, 0xCC, 0xDD},
			y:        []byte{0x55, 0x44},
			expected: []byte{0xFF, 0xFF},
			n:        2,
		},
		{
			name:     "empty x",
			x:        []byte{},
			y:        []byte{0xFF, 0xFF},
			expected: []byte{},
			n:        0,
		},
		{
			name:     "empty y",
			x:        []byte{0xFF, 0xFF},
			y:        []byte{},
			expected: []byte{},
			n:        0,
		},
		{
			name:     "single byte",
			x:        []byte{0xF0},
			y:        []byte{0x0F},
			expected: []byte{0xFF},
			n:        1,
		},
		{
			name:     "alternating bits",
			x:        []byte{0xAA, 0xAA},
			y:        []byte{0x55, 0x55},
			expected: []byte{0xFF, 0xFF},
			n:        2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dst := make([]byte, len(tt.expected))
			n := ct.OrBytes(dst, tt.x, tt.y)
			assert.Equal(t, tt.n, n, "returned length should match")
			assert.Equal(t, tt.expected, dst, "OR result should match")
		})
	}

	// Test panic on short dst
	t.Run("panic on short dst", func(t *testing.T) {
		t.Parallel()
		x := []byte{0xFF, 0xFF, 0xFF}
		y := []byte{0x00, 0x00, 0x00}
		dst := make([]byte, 2) // Too short
		assert.Panics(t, func() {
			ct.OrBytes(dst, x, y)
		}, "should panic when dst is too short")
	})
}

// TestNotBytes tests the NotBytes function
func TestNotBytes(t *testing.T) {
	tests := []struct {
		name     string
		x        []byte
		expected []byte
		n        int
	}{
		{
			name:     "all zeros to all ones",
			x:        []byte{0x00, 0x00, 0x00},
			expected: []byte{0xFF, 0xFF, 0xFF},
			n:        3,
		},
		{
			name:     "all ones to all zeros",
			x:        []byte{0xFF, 0xFF, 0xFF},
			expected: []byte{0x00, 0x00, 0x00},
			n:        3,
		},
		{
			name:     "mixed bytes",
			x:        []byte{0xF0, 0x0F, 0xAA, 0x55},
			expected: []byte{0x0F, 0xF0, 0x55, 0xAA},
			n:        4,
		},
		{
			name:     "single byte",
			x:        []byte{0xA5},
			expected: []byte{0x5A},
			n:        1,
		},
		{
			name:     "empty input",
			x:        []byte{},
			expected: []byte{},
			n:        0,
		},
		{
			name:     "alternating bits",
			x:        []byte{0xAA, 0x55},
			expected: []byte{0x55, 0xAA},
			n:        2,
		},
		{
			name:     "complex pattern",
			x:        []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
			expected: []byte{0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21, 0x0F},
			n:        8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dst := make([]byte, len(tt.expected))
			n := ct.NotBytes(dst, tt.x)
			assert.Equal(t, tt.n, n, "returned length should match")
			assert.Equal(t, tt.expected, dst, "NOT result should match")
		})
	}

	// Test panic on short dst
	t.Run("panic on short dst", func(t *testing.T) {
		t.Parallel()
		x := []byte{0xFF, 0xFF, 0xFF}
		dst := make([]byte, 2) // Too short
		assert.Panics(t, func() {
			ct.NotBytes(dst, x)
		}, "should panic when dst is too short")
	})

	// Test involution property: NOT(NOT(x)) = x
	t.Run("involution property", func(t *testing.T) {
		t.Parallel()
		original := []byte{0x12, 0x34, 0x56, 0x78, 0x9A}
		tmp := make([]byte, len(original))
		result := make([]byte, len(original))

		ct.NotBytes(tmp, original)
		ct.NotBytes(result, tmp)

		assert.Equal(t, original, result, "NOT(NOT(x)) should equal x")
	})
}

// TestXorBytes tests the XorBytes function
func TestPadLeft(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		src      []byte
		dstLen   int
		expected []byte
	}{
		{
			name:     "pad empty slice",
			src:      []byte{},
			dstLen:   4,
			expected: []byte{0, 0, 0, 0},
		},
		{
			name:     "pad smaller slice",
			src:      []byte{0xAB, 0xCD},
			dstLen:   4,
			expected: []byte{0, 0, 0xAB, 0xCD},
		},
		{
			name:     "exact size",
			src:      []byte{0xAB, 0xCD},
			dstLen:   2,
			expected: []byte{0xAB, 0xCD},
		},
		{
			name:     "truncate larger slice",
			src:      []byte{0x11, 0x22, 0x33, 0x44},
			dstLen:   2,
			expected: []byte{0x33, 0x44}, // Takes the last 2 bytes
		},
		{
			name:     "single byte pad",
			src:      []byte{0xFF},
			dstLen:   3,
			expected: []byte{0, 0, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dst := make([]byte, tt.dstLen)
			ct.PadLeft(dst, tt.src)
			assert.Equal(t, tt.expected, dst)
		})
	}
}

func TestXorBytes(t *testing.T) {
	tests := []struct {
		name     string
		x, y     []byte
		expected []byte
		n        int
	}{
		{
			name:     "simple XOR",
			x:        []byte{0xFF, 0x00, 0xAA},
			y:        []byte{0x00, 0xFF, 0x55},
			expected: []byte{0xFF, 0xFF, 0xFF},
			n:        3,
		},
		{
			name:     "same values give zero",
			x:        []byte{0xAA, 0xBB, 0xCC},
			y:        []byte{0xAA, 0xBB, 0xCC},
			expected: []byte{0x00, 0x00, 0x00},
			n:        3,
		},
		{
			name:     "XOR with zeros",
			x:        []byte{0xAA, 0xBB, 0xCC},
			y:        []byte{0x00, 0x00, 0x00},
			expected: []byte{0xAA, 0xBB, 0xCC},
			n:        3,
		},
		{
			name:     "XOR with ones",
			x:        []byte{0xAA, 0xBB, 0xCC},
			y:        []byte{0xFF, 0xFF, 0xFF},
			expected: []byte{0x55, 0x44, 0x33},
			n:        3,
		},
		{
			name:     "different lengths - min used",
			x:        []byte{0xFF, 0xFF, 0xFF, 0xFF},
			y:        []byte{0xAA, 0xAA},
			expected: []byte{0x55, 0x55},
			n:        2,
		},
		{
			name:     "empty x",
			x:        []byte{},
			y:        []byte{0xFF, 0xFF},
			expected: []byte{},
			n:        0,
		},
		{
			name:     "single byte",
			x:        []byte{0xF0},
			y:        []byte{0x0F},
			expected: []byte{0xFF},
			n:        1,
		},
		{
			name:     "alternating bits",
			x:        []byte{0xAA, 0xAA},
			y:        []byte{0x55, 0x55},
			expected: []byte{0xFF, 0xFF},
			n:        2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dst := make([]byte, len(tt.expected))
			n := ct.XorBytes(dst, tt.x, tt.y)
			assert.Equal(t, tt.n, n, "returned length should match")
			assert.Equal(t, tt.expected, dst, "XOR result should match")
		})
	}

	// Test XOR properties
	t.Run("XOR properties", func(t *testing.T) {
		t.Parallel()
		x := []byte{0x12, 0x34, 0x56, 0x78}
		y := []byte{0x9A, 0xBC, 0xDE, 0xF0}
		zeros := []byte{0x00, 0x00, 0x00, 0x00}
		ones := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		// Property: x XOR x = 0
		dst := make([]byte, len(x))
		ct.XorBytes(dst, x, x)
		assert.Equal(t, zeros, dst, "x XOR x should be zero")

		// Property: x XOR 0 = x
		ct.XorBytes(dst, x, zeros)
		assert.Equal(t, x, dst, "x XOR 0 should be x")

		// Property: x XOR 1s = NOT x
		ct.XorBytes(dst, x, ones)
		notX := make([]byte, len(x))
		ct.NotBytes(notX, x)
		assert.Equal(t, notX, dst, "x XOR 1s should be NOT x")

		// Property: Commutative - x XOR y = y XOR x
		dst1 := make([]byte, len(x))
		dst2 := make([]byte, len(x))
		ct.XorBytes(dst1, x, y)
		ct.XorBytes(dst2, y, x)
		assert.Equal(t, dst1, dst2, "XOR should be commutative")

		// Property: x XOR (x XOR y) = y
		tmp := make([]byte, len(x))
		ct.XorBytes(tmp, x, y)
		ct.XorBytes(dst, x, tmp)
		assert.Equal(t, y, dst, "x XOR (x XOR y) should equal y")
	})
}

// TestByteOperationsCombined tests combinations of byte operations
func TestByteOperationsCombined(t *testing.T) {
	t.Run("De Morgan's Law: NOT(A AND B) = NOT(A) OR NOT(B)", func(t *testing.T) {
		t.Parallel()
		a := []byte{0xF0, 0x0F, 0xAA, 0x55}
		b := []byte{0x0F, 0xF0, 0x55, 0xAA}

		// Left side: NOT(A AND B)
		andResult := make([]byte, len(a))
		ct.AndBytes(andResult, a, b)
		leftSide := make([]byte, len(a))
		ct.NotBytes(leftSide, andResult)

		// Right side: NOT(A) OR NOT(B)
		notA := make([]byte, len(a))
		notB := make([]byte, len(b))
		ct.NotBytes(notA, a)
		ct.NotBytes(notB, b)
		rightSide := make([]byte, len(a))
		ct.OrBytes(rightSide, notA, notB)

		assert.Equal(t, leftSide, rightSide, "De Morgan's Law should hold")
	})

	t.Run("De Morgan's Law: NOT(A OR B) = NOT(A) AND NOT(B)", func(t *testing.T) {
		t.Parallel()
		a := []byte{0xF0, 0x0F, 0xAA, 0x55}
		b := []byte{0x0F, 0xF0, 0x55, 0xAA}

		// Left side: NOT(A OR B)
		orResult := make([]byte, len(a))
		ct.OrBytes(orResult, a, b)
		leftSide := make([]byte, len(a))
		ct.NotBytes(leftSide, orResult)

		// Right side: NOT(A) AND NOT(B)
		notA := make([]byte, len(a))
		notB := make([]byte, len(b))
		ct.NotBytes(notA, a)
		ct.NotBytes(notB, b)
		rightSide := make([]byte, len(a))
		ct.AndBytes(rightSide, notA, notB)

		assert.Equal(t, leftSide, rightSide, "De Morgan's Law should hold")
	})

	t.Run("XOR using AND, OR, NOT: A XOR B = (A OR B) AND NOT(A AND B)", func(t *testing.T) {
		t.Parallel()
		a := []byte{0xF0, 0x0F, 0xAA, 0x55}
		b := []byte{0x0F, 0xF0, 0x55, 0xAA}

		// Direct XOR
		xorDirect := make([]byte, len(a))
		ct.XorBytes(xorDirect, a, b)

		// XOR using other operations
		orResult := make([]byte, len(a))
		ct.OrBytes(orResult, a, b)

		andResult := make([]byte, len(a))
		ct.AndBytes(andResult, a, b)

		notAndResult := make([]byte, len(a))
		ct.NotBytes(notAndResult, andResult)

		xorIndirect := make([]byte, len(a))
		ct.AndBytes(xorIndirect, orResult, notAndResult)

		assert.Equal(t, xorDirect, xorIndirect, "XOR should equal (A OR B) AND NOT(A AND B)")
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

// TestCSelectInts tests the conditional select for slices
func TestCSelectInts(t *testing.T) {
	t.Parallel()

	t.Run("select x0 when choice=0", func(t *testing.T) {
		t.Parallel()
		x0 := []uint64{1, 2, 3, 4}
		x1 := []uint64{5, 6, 7, 8}
		result := ct.CSelectInts(ct.Zero, x0, x1)
		assert.Equal(t, x0, result)
	})

	t.Run("select x1 when choice=1", func(t *testing.T) {
		t.Parallel()
		x0 := []uint64{1, 2, 3, 4}
		x1 := []uint64{5, 6, 7, 8}
		result := ct.CSelectInts(ct.One, x0, x1)
		assert.Equal(t, x1, result)
	})

	t.Run("empty slices", func(t *testing.T) {
		t.Parallel()
		x0 := []uint64{}
		x1 := []uint64{}
		result := ct.CSelectInts(ct.Zero, x0, x1)
		assert.Equal(t, x0, result)
	})

	t.Run("single element", func(t *testing.T) {
		t.Parallel()
		x0 := []int64{-42}
		x1 := []int64{42}
		assert.Equal(t, x0, ct.CSelectInts(ct.Zero, x0, x1))
		assert.Equal(t, x1, ct.CSelectInts(ct.One, x0, x1))
	})

	t.Run("panic on different lengths", func(t *testing.T) {
		t.Parallel()
		x0 := []uint64{1, 2}
		x1 := []uint64{1, 2, 3}
		assert.Panics(t, func() {
			ct.CSelectInts(ct.Zero, x0, x1)
		})
	})
}

// TestCMOVInts tests the conditional move for slices
func TestCMOVInts(t *testing.T) {
	t.Parallel()

	t.Run("move when yes=1", func(t *testing.T) {
		t.Parallel()
		dst := []uint64{1, 2, 3, 4}
		src := []uint64{5, 6, 7, 8}
		ct.CMOVInts(dst, src, ct.One)
		assert.Equal(t, []uint64{5, 6, 7, 8}, dst, "dst should be updated when yes=1")
	})

	t.Run("no move when yes=0", func(t *testing.T) {
		t.Parallel()
		dst := []uint64{1, 2, 3, 4}
		src := []uint64{5, 6, 7, 8}
		original := append([]uint64{}, dst...)
		ct.CMOVInts(dst, src, ct.Zero)
		assert.Equal(t, original, dst, "dst should be unchanged when yes=0")
	})

	t.Run("signed integers", func(t *testing.T) {
		t.Parallel()
		dst := []int64{-1, -2, -3}
		src := []int64{10, 20, 30}
		ct.CMOVInts(dst, src, ct.One)
		assert.Equal(t, []int64{10, 20, 30}, dst)
	})

	t.Run("empty slices", func(t *testing.T) {
		t.Parallel()
		dst := []uint64{}
		src := []uint64{}
		ct.CMOVInts(dst, src, ct.One) // Should not panic
		assert.Equal(t, []uint64{}, dst)
	})

	t.Run("panic on different lengths", func(t *testing.T) {
		t.Parallel()
		dst := []uint64{1, 2}
		src := []uint64{1, 2, 3}
		assert.Panics(t, func() {
			ct.CMOVInts(dst, src, ct.One)
		})
	})

	t.Run("alias safety", func(t *testing.T) {
		t.Parallel()
		// Test when dst and src point to same slice
		slice := []uint64{1, 2, 3}
		ct.CMOVInts(slice, slice, ct.One)
		assert.Equal(t, []uint64{1, 2, 3}, slice)
	})
}

// TestCSwapInts tests the conditional swap for slices
func TestCSwapInts(t *testing.T) {
	t.Parallel()

	t.Run("swap when yes=1", func(t *testing.T) {
		t.Parallel()
		x := []uint64{1, 2, 3, 4}
		y := []uint64{5, 6, 7, 8}
		ct.CSwapInts(x, y, ct.One)
		assert.Equal(t, []uint64{5, 6, 7, 8}, x, "x should be swapped when yes=1")
		assert.Equal(t, []uint64{1, 2, 3, 4}, y, "y should be swapped when yes=1")
	})

	t.Run("no swap when yes=0", func(t *testing.T) {
		t.Parallel()
		x := []uint64{1, 2, 3, 4}
		y := []uint64{5, 6, 7, 8}
		origX := append([]uint64{}, x...)
		origY := append([]uint64{}, y...)
		ct.CSwapInts(x, y, ct.Zero)
		assert.Equal(t, origX, x, "x should be unchanged when yes=0")
		assert.Equal(t, origY, y, "y should be unchanged when yes=0")
	})

	t.Run("signed integers", func(t *testing.T) {
		t.Parallel()
		x := []int64{-1, -2, -3}
		y := []int64{10, 20, 30}
		ct.CSwapInts(x, y, ct.One)
		assert.Equal(t, []int64{10, 20, 30}, x)
		assert.Equal(t, []int64{-1, -2, -3}, y)
	})

	t.Run("empty slices", func(t *testing.T) {
		t.Parallel()
		x := []uint64{}
		y := []uint64{}
		ct.CSwapInts(x, y, ct.One)
		assert.Equal(t, []uint64{}, x)
		assert.Equal(t, []uint64{}, y)
	})

	t.Run("single element", func(t *testing.T) {
		t.Parallel()
		x := []uint64{42}
		y := []uint64{84}
		ct.CSwapInts(x, y, ct.One)
		assert.Equal(t, []uint64{84}, x)
		assert.Equal(t, []uint64{42}, y)
	})

	t.Run("panic on different lengths", func(t *testing.T) {
		t.Parallel()
		x := []uint64{1, 2}
		y := []uint64{1, 2, 3}
		assert.Panics(t, func() {
			ct.CSwapInts(x, y, ct.One)
		})
	})

	t.Run("alias safety", func(t *testing.T) {
		t.Parallel()
		// Test when x and y point to same slice
		slice := []uint64{1, 2, 3}
		ct.CSwapInts(slice, slice, ct.One)
		assert.Equal(t, []uint64{1, 2, 3}, slice, "swapping with self should be no-op")
	})

	t.Run("double swap returns to original", func(t *testing.T) {
		t.Parallel()
		x := []uint64{1, 2, 3}
		y := []uint64{4, 5, 6}
		origX := append([]uint64{}, x...)
		origY := append([]uint64{}, y...)

		// Swap twice
		ct.CSwapInts(x, y, ct.One)
		ct.CSwapInts(x, y, ct.One)

		assert.Equal(t, origX, x, "double swap should return to original")
		assert.Equal(t, origY, y, "double swap should return to original")
	})
}

// Benchmark functions
func BenchmarkConstantTime(b *testing.B) {
	b.Run("IsZero", func(b *testing.B) {
		var result ct.Choice
		for range b.N {
			result = ct.IsZero(uint64(b.N))
		}
		_ = result
	})

	b.Run("Equal", func(b *testing.B) {
		var result ct.Choice
		for range b.N {
			result = ct.Equal(uint64(b.N), uint64(b.N+1))
		}
		_ = result
	})

	b.Run("SelectInteger", func(b *testing.B) {
		var result uint64
		for range b.N {
			result = ct.CSelectInt(ct.Choice(b.N&1), uint64(b.N), uint64(b.N+1))
		}
		_ = result
	})

	b.Run("Isqrt64", func(b *testing.B) {
		var result uint64
		for range b.N {
			result = ct.Isqrt64(uint64(b.N))
		}
		_ = result
	})

	b.Run("BytesCompare", func(b *testing.B) {
		x := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		y := []byte{1, 2, 3, 4, 5, 6, 7, 9}
		var lt, eq, gt ct.Bool
		for range b.N {
			lt, eq, gt = ct.CompareBytes(x, y)
		}
		_ = lt
		_ = eq
		_ = gt
	})
}
