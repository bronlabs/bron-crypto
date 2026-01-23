//go:build !purego && !nobignum

package boring_test

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
)

func Test_LongDhGen(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	const reps = 4
	const bits = 512

	for i := 0; i < reps; i++ {
		p := boring.NewDiffieHellmanGroup().GenerateParameters(bits).GetP()
		pBytes, err := p.Bytes()
		require.NoError(t, err)

		pNat := new(big.Int).SetBytes(pBytes)
		qNat := new(big.Int).Rsh(pNat, 1)

		require.Equal(t, bits, pNat.BitLen())
		require.Equal(t, bits-1, qNat.BitLen())
		require.True(t, pNat.ProbablyPrime(5))
		require.True(t, qNat.ProbablyPrime(5))
	}

	runtime.GC()
}
