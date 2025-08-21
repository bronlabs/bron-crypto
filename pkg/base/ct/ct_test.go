package ct_test

import (
	"math"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChoice tests the Choice/Bool type and its Not() method
func TestChoice(t *testing.T) {
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
			assert.Equal(t, tt.expected, tt.choice.Not())
		})
	}
}

// TestCSelect tests the generic CSelect function
func TestCSelect(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		a, b := 42, 100
		assert.Equal(t, b, ct.CSelect(ct.Zero, a, b), "CSelect(0) should return b")
		assert.Equal(t, a, ct.CSelect(ct.One, a, b), "CSelect(1) should return a")
	})

	t.Run("struct", func(t *testing.T) {
		type TestStruct struct {
			X int
			Y string
		}
		a := TestStruct{X: 1, Y: "hello"}
		b := TestStruct{X: 2, Y: "world"}
		
		assert.Equal(t, b, ct.CSelect(ct.Zero, a, b))
		assert.Equal(t, a, ct.CSelect(ct.One, a, b))
	})

	t.Run("zero-sized", func(t *testing.T) {
		type Empty struct{}
		a, b := Empty{}, Empty{}
		// Should not panic for zero-sized types
		assert.NotPanics(t, func() {
			_ = ct.CSelect(ct.Zero, a, b)
			_ = ct.CSelect(ct.One, a, b)
		})
	})

	t.Run("slices", func(t *testing.T) {
		a := []int{1, 2, 3}
		b := []int{4, 5, 6}
		
		got0 := ct.CSelect(ct.Zero, a, b)
		assert.Equal(t, b, got0)
		
		got1 := ct.CSelect(ct.One, a, b)
		assert.Equal(t, a, got1)
	})

	t.Run("pointers", func(t *testing.T) {
		x, y := 42, 100
		a, b := &x, &y
		
		assert.Equal(t, b, ct.CSelect(ct.Zero, a, b))
		assert.Equal(t, a, ct.CSelect(ct.One, a, b))
	})

	t.Run("interface", func(t *testing.T) {
		var a, b any = 42, "hello"
		
		assert.Equal(t, b, ct.CSelect(ct.Zero, a, b))
		assert.Equal(t, a, ct.CSelect(ct.One, a, b))
	})

	t.Run("large_struct", func(t *testing.T) {
		type LargeStruct struct {
			Data [1024]byte
			ID   int
		}
		var a, b LargeStruct
		a.ID = 1
		b.ID = 2
		a.Data[0] = 0xAA
		b.Data[0] = 0xBB
		
		got0 := ct.CSelect(ct.Zero, a, b)
		assert.Equal(t, b.ID, got0.ID)
		assert.Equal(t, b.Data[0], got0.Data[0])
		
		got1 := ct.CSelect(ct.One, a, b)
		assert.Equal(t, a.ID, got1.ID)
		assert.Equal(t, a.Data[0], got1.Data[0])
	})
}

// TestCMOV tests the CMOV function
func TestCMOV(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		dst := 42
		src := 100
		
		// Test no-op when choice=0
		ct.CMOV(&dst, ct.Zero, &src)
		assert.Equal(t, 42, dst, "CMOV(0) should not modify dst")
		
		// Test move when choice=1
		ct.CMOV(&dst, ct.One, &src)
		assert.Equal(t, 100, dst, "CMOV(1) should move src to dst")
	})
	
	t.Run("struct", func(t *testing.T) {
		type TestStruct struct {
			X int
			Y string
		}
		dst := TestStruct{X: 1, Y: "hello"}
		src := TestStruct{X: 2, Y: "world"}
		
		// Test no-op when choice=0
		original := dst
		ct.CMOV(&dst, ct.Zero, &src)
		assert.Equal(t, original, dst)
		
		// Test move when choice=1
		ct.CMOV(&dst, ct.One, &src)
		assert.Equal(t, src, dst)
	})
	
	t.Run("array", func(t *testing.T) {
		dst := [4]int{1, 2, 3, 4}
		src := [4]int{5, 6, 7, 8}
		
		// Test no-op when choice=0
		original := dst
		ct.CMOV(&dst, ct.Zero, &src)
		assert.Equal(t, original, dst)
		
		// Test move when choice=1
		ct.CMOV(&dst, ct.One, &src)
		assert.Equal(t, src, dst)
	})

	t.Run("zero-sized", func(t *testing.T) {
		type Empty struct{}
		var dst, src Empty
		// Should not panic
		assert.NotPanics(t, func() {
			ct.CMOV(&dst, ct.Zero, &src)
			ct.CMOV(&dst, ct.One, &src)
		})
	})
}

// TestCSwap tests the CSwap function
func TestCSwap(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		x, y := 42, 100
		
		// Test no-op when choice=0
		ct.CSwap(&x, &y, ct.Zero)
		assert.Equal(t, 42, x)
		assert.Equal(t, 100, y)
		
		// Test swap when choice=1
		ct.CSwap(&x, &y, ct.One)
		assert.Equal(t, 100, x)
		assert.Equal(t, 42, y)
	})
	
	t.Run("struct", func(t *testing.T) {
		type TestStruct struct {
			X int
			Y string
		}
		a := TestStruct{X: 1, Y: "hello"}
		b := TestStruct{X: 2, Y: "world"}
		
		// Test no-op when choice=0
		origA, origB := a, b
		ct.CSwap(&a, &b, ct.Zero)
		assert.Equal(t, origA, a)
		assert.Equal(t, origB, b)
		
		// Test swap when choice=1
		ct.CSwap(&a, &b, ct.One)
		assert.Equal(t, origB, a)
		assert.Equal(t, origA, b)
	})
	
	t.Run("self-swap", func(t *testing.T) {
		x := 42
		// Self-swap should work without issues (alias-safe)
		ct.CSwap(&x, &x, ct.One)
		assert.Equal(t, 42, x, "Self-swap should not change value")
	})
	
	t.Run("large_array", func(t *testing.T) {
		var a, b [256]byte
		for i := range a {
			a[i] = byte(i)
			b[i] = byte(255 - i)
		}
		
		// Save originals
		origA, origB := a, b
		
		// Test no-op when choice=0
		ct.CSwap(&a, &b, ct.Zero)
		assert.Equal(t, origA, a)
		assert.Equal(t, origB, b)
		
		// Test swap when choice=1
		ct.CSwap(&a, &b, ct.One)
		assert.Equal(t, origB, a)
		assert.Equal(t, origA, b)
	})
}

// TestIsZero tests the IsZero function for various integer types
func TestIsZero(t *testing.T) {
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
	// Test unsigned comparisons
	t.Run("unsigned", func(t *testing.T) {
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
			gt, eq, lt := ct.Cmp(tt.x, tt.y)
			assert.Equal(t, tt.gt, gt, "gt")
			assert.Equal(t, tt.eq, eq, "eq")
			assert.Equal(t, tt.lt, lt, "lt")
		})
	}
}

// TestSelectInteger tests the SelectInteger function for integers
func TestSelectInteger(t *testing.T) {
	// Test with various integer types
	t.Run("uint8", func(t *testing.T) {
		var a, b uint8 = 42, 100
		assert.Equal(t, a, ct.SelectInteger(ct.Zero, a, b))
		assert.Equal(t, b, ct.SelectInteger(ct.One, a, b))
	})

	t.Run("int64", func(t *testing.T) {
		var a, b int64 = -42, 100
		assert.Equal(t, a, ct.SelectInteger(ct.Zero, a, b))
		assert.Equal(t, b, ct.SelectInteger(ct.One, a, b))
	})

	t.Run("boundary", func(t *testing.T) {
		// Test with boundary values
		var a, b int64 = math.MinInt64, math.MaxInt64
		assert.Equal(t, a, ct.SelectInteger(ct.Zero, a, b))
		assert.Equal(t, b, ct.SelectInteger(ct.One, a, b))
	})
}


// TestMinMax tests the Min and Max functions
func TestMinMax(t *testing.T) {
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
			assert.Equal(t, tt.min, ct.Min(tt.a, tt.b), "Min(%d, %d)", tt.a, tt.b)
			assert.Equal(t, tt.max, ct.Max(tt.a, tt.b), "Max(%d, %d)", tt.a, tt.b)
		})
	}
}

// TestIsqrt64 tests the constant-time integer square root
func TestIsqrt64(t *testing.T) {
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
			assert.Equal(t, tt.expected, ct.Isqrt64(tt.n), "Isqrt64(%d)", tt.n)
		})
	}
}

// TestIsSigned tests the IsSigned function
func TestIsSigned(t *testing.T) {
	assert.Equal(t, ct.True, ct.IsSigned[int8]())
	assert.Equal(t, ct.True, ct.IsSigned[int16]())
	assert.Equal(t, ct.True, ct.IsSigned[int32]())
	assert.Equal(t, ct.True, ct.IsSigned[int64]())
	assert.Equal(t, ct.True, ct.IsSigned[int]())
	
	assert.Equal(t, ct.False, ct.IsSigned[uint8]())
	assert.Equal(t, ct.False, ct.IsSigned[uint16]())
	assert.Equal(t, ct.False, ct.IsSigned[uint32]())
	assert.Equal(t, ct.False, ct.IsSigned[uint64]())
	assert.Equal(t, ct.False, ct.IsSigned[uint]())
}

// TestLessU64 tests unsigned 64-bit comparison
func TestLessU64(t *testing.T) {
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
			assert.Equal(t, tt.expected, ct.LessU64(tt.x, tt.y), "LessU64(%d, %d)", tt.x, tt.y)
		})
	}
}

// TestLessI64 tests signed 64-bit comparison
func TestLessI64(t *testing.T) {
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
			assert.Equal(t, tt.expected, ct.LessI64(tt.x, tt.y), "LessI64(%d, %d)", tt.x, tt.y)
		})
	}
}

// TestSliceEachEqual tests the SliceEachEqual function
func TestSliceEachEqual(t *testing.T) {
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
			assert.Equal(t, tt.expected, ct.SliceEachEqual(tt.s, tt.e))
		})
	}
}

// TestSliceEqual tests the SliceEqual function
func TestSliceEqual(t *testing.T) {
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
			assert.Equal(t, tt.expected, ct.SliceEqual(tt.x, tt.y))
		})
	}

	t.Run("panic on different lengths", func(t *testing.T) {
		assert.Panics(t, func() {
			ct.SliceEqual([]uint8{1, 2}, []uint8{1, 2, 3})
		})
	})
}

// TestSliceIsZero tests the SliceIsZero function
func TestSliceIsZero(t *testing.T) {
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
			assert.Equal(t, tt.expected, ct.SliceIsZero(tt.s))
		})
	}
}

// TestBytesCompare tests the BytesCompare function
func TestBytesCompare(t *testing.T) {
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
			lt, eq, gt := ct.BytesCompare(tt.x, tt.y)
			assert.Equal(t, tt.lt, lt, "lt")
			assert.Equal(t, tt.eq, eq, "eq")
			assert.Equal(t, tt.gt, gt, "gt")
		})
	}
}

// TestConstantTime is a basic smoke test for constant-time properties
func TestConstantTime(t *testing.T) {
	// This is a basic smoke test - true constant-time verification requires
	// specialized tools like dudect or manual assembly inspection

	// Test that SelectInteger returns consistent results
	t.Run("SelectInteger consistency", func(t *testing.T) {
		for i := range 1000 {
			a, b := uint64(i), uint64(i+1000)
			assert.Equal(t, a, ct.SelectInteger(ct.Zero, a, b))
			assert.Equal(t, b, ct.SelectInteger(ct.One, a, b))
		}
	})

	// Test that comparisons are consistent
	t.Run("Comparison consistency", func(t *testing.T) {
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
			result = ct.SelectInteger(ct.Choice(b.N&1), uint64(b.N), uint64(b.N+1))
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
			lt, eq, gt = ct.BytesCompare(x, y)
		}
		_ = lt
		_ = eq
		_ = gt
	})
}