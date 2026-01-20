package internal_test

import (
	crand "crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct/internal"
)

func Test_EuclideanDiv(t *testing.T) {
	t.Parallel()

	const iters = 1024
	const bits = 4096
	prng := crand.Reader

	for range iters {
		var xBytes, yBytes [bits / 8]byte
		_, err := io.ReadFull(prng, xBytes[:])
		require.NoError(t, err)
		_, err = io.ReadFull(prng, yBytes[:])
		require.NoError(t, err)

		x := new(saferith.Nat).SetBytes(xBytes[:])
		y := new(saferith.Nat).SetBytes(yBytes[:])
		actualQ, actualR := internal.EuclideanDiv(new(saferith.Nat), new(saferith.Nat), x, y)
		expectedQ := new(big.Int).Div(x.Big(), y.Big())
		expectedR := new(big.Int).Mod(x.Big(), y.Big())

		require.True(t, actualQ.Big().Cmp(expectedQ) == 0)
		require.True(t, actualR.Big().Cmp(expectedR) == 0)
	}
}
