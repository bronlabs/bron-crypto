package ct_test

import (
	"math/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
)

func Test_ConstantTimeEq(t *testing.T) {
	// Try all combinations of x and y in [0, 20].
	for x := uint64(0); x < 20; x++ {
		for y := uint64(0); y < 20; y++ {
			// Calculate x == y and compare with ConstantTimeEq(x, y).
			expected := 0
			if x == y {
				expected = 1
			}
			actual := ct.ConstantTimeEq(x, y)
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
		actual := ct.ConstantTimeEq(x, y)
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
			actual := ct.ConstantTimeGt(x, y)
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
		actual := ct.ConstantTimeGt(x, y)
		if expected != actual {
			t.Errorf("ConstantTimeGt(%d, %d) = %d, expected %d", x, y, actual, expected)
		}
	}
}
