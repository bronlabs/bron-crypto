package bf128_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

const reps = 128

func TestZero(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	zero := bf128.NewField().Zero()
	require.True(t, zero.IsZero())
	require.False(t, zero.IsOne())
	_, err := zero.TryInv()
	require.Error(t, err)
	for range reps {
		x, err := bf128.NewField().Random(prng)
		require.NoError(t, err)
		require.True(t, x.Add(zero).Equal(x))
		require.True(t, x.Mul(zero).Equal(zero))
	}
}

func TestOne(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	one := bf128.NewField().One()
	require.False(t, one.IsZero())
	require.True(t, one.IsOne())
	for range reps {
		x, err := bf128.NewField().RandomNonZero(prng)
		require.NoError(t, err)
		require.True(t, x.Mul(one).Equal(x))
	}
}

func TestInv(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	for range reps {
		x, err := bf128.NewField().RandomNonZero(prng)
		require.NoError(t, err)
		xInv, err := x.TryInv()
		require.NoError(t, err)
		y := x.Mul(xInv)
		require.True(t, y.IsOne())
	}
}
