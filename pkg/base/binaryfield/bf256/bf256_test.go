package bf256_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/binaryfield/bf256"
)

func TestF2e256Mult(t *testing.T) {
	t.Parallel()
	nIter := 100
	for range nIter {
		x, err := bf256.NewField().Random(crand.Reader)
		y := x.Clone()
		require.NoError(t, err)
		for i := 0; i < 255; i++ { // Little fermat's theorem.
			y = y.Mul(y)
			require.False(t, x.Equal(y))
		}
		require.True(t, x.Equal(y.Mul(y)))
	}
}

func TestIsAdditiveIdentity(t *testing.T) {
	t.Parallel()
	zero := bf256.NewField().AdditiveIdentity()
	require.True(t, zero.IsAdditiveIdentity())
	one := bf256.NewField().MultiplicativeIdentity()
	require.False(t, one.IsAdditiveIdentity())
}
