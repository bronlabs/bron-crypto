package bf128_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
)

const reps = 128

func TestZero(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	zero := bf128.NewField().Zero()
	require.True(t, zero.IsZero())
	require.False(t, zero.IsOne())
	for range reps {
		x, err := bf128.NewField().Random(prng)
		require.NoError(t, err)
		require.True(t, x.Add(zero).Equal(x))
		require.True(t, x.Mul(zero).Equal(zero))
	}
}

func TestOne(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	one := bf128.NewField().One()
	require.False(t, one.IsZero())
	require.True(t, one.IsOne())
	for range reps {
		x, err := bf128.NewField().Random(prng)
		require.NoError(t, err)
		require.True(t, x.Mul(one).Equal(x))
	}
}
