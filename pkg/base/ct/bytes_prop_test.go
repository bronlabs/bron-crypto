package ct_test

import (
	"bytes"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
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

func TestDeMorgan_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		sliceLength := rapid.IntRange(1, 100).Draw(t, "sliceLength")
		x := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "x")
		y := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "y")

		notX := make([]byte, sliceLength)
		ok := ct.NotBytes(notX, x)
		require.NotZero(t, ok)
		notY := make([]byte, sliceLength)
		ok = ct.NotBytes(notY, y)
		require.NotZero(t, ok)

		lhs1 := make([]byte, sliceLength)
		ok = ct.AndBytes(lhs1, x, y)
		require.NotZero(t, ok)
		ok = ct.NotBytes(lhs1, lhs1)
		require.NotZero(t, ok)

		rhs1 := make([]byte, sliceLength)
		ok = ct.OrBytes(rhs1, notX, notY)
		require.NotZero(t, ok)

		require.Equal(t, lhs1, rhs1, "not (a & b) != (not a) | (not b)")

		lhs2 := make([]byte, sliceLength)
		ok = ct.OrBytes(lhs2, x, y)
		require.NotZero(t, ok)
		ok = ct.NotBytes(lhs2, lhs2)
		require.NotZero(t, ok)

		rhs2 := make([]byte, sliceLength)
		ok = ct.AndBytes(rhs2, notX, notY)
		require.NotZero(t, ok)

		require.Equal(t, lhs2, rhs2, "not (a | b) != (not a) & (not b)")
	})
}
