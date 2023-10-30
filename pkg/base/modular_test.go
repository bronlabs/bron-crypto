package base_test

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
)

func Test_CeilDiv(t *testing.T) {
	// Try all combinations of a and b in [0, 20].
	for a := 1; a < 20; a++ {
		for b := 1; b < 20; b++ {
			// Calculate ceil(a/b) and compare with CeilDiv(a, b).
			expected := int(math.Ceil(float64(a) / float64(b)))
			actual := base.CeilDiv(a, b)
			if expected != actual {
				t.Errorf("CeilDiv(%d, %d) = %d, expected %d", a, b, actual, expected)
			}
		}
	}
}

func Test_ConstantTimeEq(t *testing.T) {
	// Try all combinations of x and y in [0, 20].
	for x := uint64(0); x < 20; x++ {
		for y := uint64(0); y < 20; y++ {
			// Calculate x == y and compare with ConstantTimeEq(x, y).
			expected := 0
			if x == y {
				expected = 1
			}
			actual := base.ConstantTimeEq(x, y)
			if expected != actual {
				t.Errorf("ConstantTimeEq(%d, %d) = %d, expected %d", x, y, actual, expected)
			}
		}
	}
	// Try 100 random samples of x and y.
	for i := 0; i < 100; i++ {
		x, y := rand.Uint64(), rand.Uint64()
		// Calculate x == y and compare with ConstantTimeEq(x, y).
		expected := 0
		if x == y {
			expected = 1
		}
		actual := base.ConstantTimeEq(x, y)
		if expected != actual {
			t.Errorf("ConstantTimeEq(%d, %d) = %d, expected %d", x, y, actual, expected)
		}
	}
}

func Test_ConstantTimeGt(t *testing.T) {
	// Try all combinations of x and y in [0, 20].
	for x := uint64(0); x < 20; x++ {
		for y := uint64(0); y < 20; y++ {
			// Calculate x > y and compare with ConstantTimeGt(x, y).
			expected := 0
			if x > y {
				expected = 1
			}
			actual := base.ConstantTimeGt(x, y)
			if expected != actual {
				t.Errorf("ConstantTimeGt(%d, %d) = %d, expected %d", x, y, actual, expected)
			}
		}
	}
	// Try 100 random samples of x and y.
	for i := 0; i < 100; i++ {
		x, y := rand.Uint64(), rand.Uint64()
		// Calculate x > y and compare with ConstantTimeGt(x, y).
		expected := 0
		if x > y {
			expected = 1
		}
		actual := base.ConstantTimeGt(x, y)
		if expected != actual {
			t.Errorf("ConstantTimeGt(%d, %d) = %d, expected %d", x, y, actual, expected)
		}
	}
}

func Test_FloorLog2(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		arg      int
		expected int
	}{
		{1, 0},
		{7, 2},
		{8, 3},
		{15, 3},
		{16, 4},
		{253, 7},
		{254, 7},
		{255, 7},
		{256, 8},
		{257, 8},
		{258, 8},
	}

	for _, testCase := range testCases {
		arg := testCase.arg
		expected := testCase.expected
		t.Run(fmt.Sprintf("floor(log2(%d)) = %d", arg, expected), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, base.FloorLog2(arg), expected)
		})
	}
}

func Test_CeilLog2(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		arg      int
		expected int
	}{
		{1, 0},
		{7, 3},
		{8, 3},
		{9, 4},
		{15, 4},
		{16, 4},
		{253, 8},
		{254, 8},
		{255, 8},
		{256, 8},
		{257, 9},
		{258, 9},
	}

	for _, testCase := range testCases {
		arg := testCase.arg
		expected := testCase.expected
		t.Run(fmt.Sprintf("ceil(log2(%d)) = %d", arg, expected), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, base.CeilLog2(arg), expected)
		})
	}
}
