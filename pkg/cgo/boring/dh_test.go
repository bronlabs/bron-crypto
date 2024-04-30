//go:build !purego && !nobignum

package boring_test

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/cgo/boring"
)

func Test_LongDhGen(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	const reps = 32
	const bits = 1024

	for i := 0; i < reps; i++ {
		dhGroup, err := boring.NewDiffieHellmanGroup()
		require.NoError(t, err)

		dhGroup, err = dhGroup.GenerateParameters(bits)
		require.NoError(t, err)

		p, err := dhGroup.GetP()
		require.NoError(t, err)

		pBytes, err := p.Bytes()
		require.NoError(t, err)

		pNat := new(big.Int).SetBytes(pBytes)
		qNat := new(big.Int).Rsh(pNat, 1)

		require.Equal(t, bits, pNat.BitLen())
		require.Equal(t, bits-1, qNat.BitLen())
		require.True(t, pNat.ProbablyPrime(64))
		require.True(t, qNat.ProbablyPrime(64))
	}

	runtime.GC()
}
