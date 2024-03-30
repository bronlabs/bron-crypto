package boring_test

import (
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex/internal/boring"
)

func Test_LongDhGen(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	const reps = 32
	const bits = 1024

	println(time.Now().String())
	for i := 0; i < reps; i++ {
		p := boring.NewDiffieHellmanGroup().GenerateParameters(bits).GetP()
		pBytes, err := p.Bytes()
		require.NoError(t, err)

		pNat := new(big.Int).SetBytes(pBytes)
		qNat := new(big.Int).Rsh(pNat, 1)

		require.Equal(t, pNat.BitLen(), bits)
		require.Equal(t, qNat.BitLen(), bits-1)
		require.True(t, pNat.ProbablyPrime(64))
		require.True(t, qNat.ProbablyPrime(64))
	}
	println(time.Now().String())

	runtime.GC()
}
