package ct_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/assert"
)

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
