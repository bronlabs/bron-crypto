package base_test

import (
	"math"
	"math/rand"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/base"
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
