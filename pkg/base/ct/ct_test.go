package ct_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

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
			actual := ct.Equal(x, y)
			require.Equal(t, expected, actual, x, y)
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
		actual := ct.Equal(x, y)
		require.Equal(t, expected, actual, x, y)
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
			actual := ct.GreaterThan(x, y)
			require.Equal(t, expected, actual, x, y)
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
		actual := ct.GreaterThan(x, y)
		require.Equal(t, expected, actual, x, y)
	}
}

func TestConstantTimeIsAllZero(t *testing.T) {
	t.Parallel()
	zero := [32]byte{}
	require.Equal(t, 1, ct.IsAllZero(zero[:]))
	require.Equal(t, 0, ct.IsAllZero([]byte("something")))
}
