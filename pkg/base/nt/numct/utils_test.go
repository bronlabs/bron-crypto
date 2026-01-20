package numct_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func TestLCM(t *testing.T) {
	t.Parallel()

	t.Run("basic cases", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			a, b     uint64
			expected uint64
		}{
			{1, 1, 1},
			{2, 3, 6},
			{4, 6, 12},
			{6, 8, 24},
			{12, 18, 36},
			{15, 25, 75},
			{7, 11, 77}, // coprime
			{12, 12, 12},
			{1, 100, 100},
			{100, 1, 100},
		}

		for _, tc := range cases {
			var out numct.Nat
			a, b := numct.NewNat(tc.a), numct.NewNat(tc.b)
			numct.LCM(&out, a, b)
			require.Equal(t, tc.expected, out.Uint64(), "lcm(%d, %d) should be %d", tc.a, tc.b, tc.expected)
		}
	})

	t.Run("commutativity", func(t *testing.T) {
		t.Parallel()

		pairs := [][2]uint64{
			{12, 18},
			{7, 13},
			{100, 35},
			{1024, 768},
		}

		for _, pair := range pairs {
			var out1, out2 numct.Nat
			a, b := numct.NewNat(pair[0]), numct.NewNat(pair[1])
			numct.LCM(&out1, a, b)
			numct.LCM(&out2, b, a)
			require.Equal(t, out1.Uint64(), out2.Uint64(), "lcm(%d, %d) should equal lcm(%d, %d)", pair[0], pair[1], pair[1], pair[0])
		}
	})

	t.Run("lcm identity: lcm(a,b) * gcd(a,b) = a * b", func(t *testing.T) {
		t.Parallel()

		pairs := [][2]uint64{
			{12, 18},
			{15, 25},
			{7, 11},
			{100, 35},
			{48, 180},
		}

		for _, pair := range pairs {
			a, b := numct.NewNat(pair[0]), numct.NewNat(pair[1])
			var lcmVal, gcdVal, product, lcmTimesGcd numct.Nat
			numct.LCM(&lcmVal, a, b)
			gcdVal.GCD(a, b)
			product.Mul(a, b)
			lcmTimesGcd.Mul(&lcmVal, &gcdVal)
			require.Equal(t, product.Uint64(), lcmTimesGcd.Uint64(),
				"lcm(%d,%d) * gcd(%d,%d) should equal %d * %d", pair[0], pair[1], pair[0], pair[1], pair[0], pair[1])
		}
	})

	t.Run("zero input", func(t *testing.T) {
		t.Parallel()

		// lcm(0, n) = 0 for any n
		var out numct.Nat
		numct.LCM(&out, numct.NewNat(0), numct.NewNat(5))
		require.Equal(t, uint64(0), out.Uint64(), "lcm(0, 5) should be 0")

		numct.LCM(&out, numct.NewNat(5), numct.NewNat(0))
		require.Equal(t, uint64(0), out.Uint64(), "lcm(5, 0) should be 0")

		numct.LCM(&out, numct.NewNat(0), numct.NewNat(0))
		require.Equal(t, uint64(0), out.Uint64(), "lcm(0, 0) should be 0")
	})

	t.Run("powers of primes", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			a, b     uint64
			expected uint64
		}{
			{4, 8, 8},      // 2^2, 2^3 -> 2^3
			{8, 16, 16},    // 2^3, 2^4 -> 2^4
			{9, 27, 27},    // 3^2, 3^3 -> 3^3
			{25, 125, 125}, // 5^2, 5^3 -> 5^3
		}

		for _, tc := range cases {
			var out numct.Nat
			numct.LCM(&out, numct.NewNat(tc.a), numct.NewNat(tc.b))
			require.Equal(t, tc.expected, out.Uint64(), "lcm(%d, %d) should be %d", tc.a, tc.b, tc.expected)
		}
	})

	t.Run("large numbers", func(t *testing.T) {
		t.Parallel()

		// Use big.Int as reference
		pairs := [][2]uint64{
			{123456, 789012},
			{1000000, 999999},
			{65536, 32768},
		}

		for _, pair := range pairs {
			a, b := numct.NewNat(pair[0]), numct.NewNat(pair[1])
			var out numct.Nat
			numct.LCM(&out, a, b)

			// Compute expected with big.Int
			aBig, bBig := big.NewInt(int64(pair[0])), big.NewInt(int64(pair[1]))
			gcdBig := new(big.Int).GCD(nil, nil, aBig, bBig)
			expectedBig := new(big.Int).Mul(aBig, bBig)
			expectedBig.Div(expectedBig, gcdBig)

			require.Equal(t, expectedBig.Uint64(), out.Uint64(),
				"lcm(%d, %d) should be %d", pair[0], pair[1], expectedBig.Uint64())
		}
	})

	t.Run("multi-limb numbers", func(t *testing.T) {
		t.Parallel()

		// Large primes that require multiple limbs
		p1Str := "340282366920938463463374607431768211297" // Large prime close to 2^128
		p2Str := "340282366920938463463374607431768211507" // Another large prime

		p1Big, _ := new(big.Int).SetString(p1Str, 10)
		p2Big, _ := new(big.Int).SetString(p2Str, 10)

		p1 := numct.NewNatFromBig(p1Big, p1Big.BitLen())
		p2 := numct.NewNatFromBig(p2Big, p2Big.BitLen())

		var out numct.Nat
		numct.LCM(&out, p1, p2)

		// For coprime numbers, lcm = product
		expectedBig := new(big.Int).Mul(p1Big, p2Big)
		require.Equal(t, expectedBig.String(), out.Big().String())
	})
}
