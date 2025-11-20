package ct_test

import (
	"bytes"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestCompareBytes_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		sliceLength := rapid.IntRange(0, 100).Draw(t, "sliceLength")
		x := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "x")
		y := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "y")

		lt, eq, gt := ct.CompareBytes(x, y)

		expected := bytes.Compare(x, y)
		if expected < 0 {
			require.Equal(t, ct.True, lt, "lt")
		} else if expected > 0 {
			require.Equal(t, ct.True, gt, "gt")
		} else {
			require.Equal(t, ct.True, eq, "eq")
		}
	})
}

// TestCompareBytes tests the BytesCompare function
func TestCompareBytes(t *testing.T) {
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
