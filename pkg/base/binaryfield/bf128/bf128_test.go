package bf128_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/binaryfield/bf128"
)

func TestF2e128Mult(t *testing.T) {
	t.Parallel()
	nIter := 100
	for range nIter {
		x, err := bf128.NewField().Random(crand.Reader)
		y := x.Clone()
		require.NoError(t, err)
		for i := 0; i < 127; i++ { // Little fermat's theorem.
			y = y.Mul(y)
			require.False(t, x.Equal(y))
		}
		require.True(t, x.Equal(y.Mul(y)))
	}
}

func TestIsAdditiveIdentity(t *testing.T) {
	t.Parallel()
	zero := bf128.NewField().AdditiveIdentity()
	require.True(t, zero.IsAdditiveIdentity())
	one := bf128.NewField().MultiplicativeIdentity()
	require.False(t, one.IsAdditiveIdentity())
}
