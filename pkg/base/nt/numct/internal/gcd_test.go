package internal_test

import (
	"io"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func Test_GCD(t *testing.T) {
	t.Parallel()

	const iters = 128
	const bits = 4096
	prng := pcg.NewRandomised()

	for range iters {
		var xBytes, yBytes [bits / 8]byte
		_, err := io.ReadFull(prng, xBytes[:])
		require.NoError(t, err)
		_, err = io.ReadFull(prng, yBytes[:])
		require.NoError(t, err)

		x := new(saferith.Nat).SetBytes(xBytes[:])
		y := new(saferith.Nat).SetBytes(yBytes[:])
		actualZ := internal.GCD(new(saferith.Nat), x, y).Big()
		expectedZ := new(big.Int).GCD(nil, nil, x.Big(), y.Big())

		require.True(t, expectedZ.Cmp(actualZ) == 0)
	}
}
