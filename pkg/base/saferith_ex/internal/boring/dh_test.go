package boring_test

import (
	"runtime"
	"testing"
	"time"

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
		println(i)
		_ = boring.NewDiffieHellmanGroup().GenerateParameters(bits).GetP()
		//p := dh.GetP()
		//pNat := new(big.Int).SetBytes(p.Bytes())
		//qNat := new(big.Int).Rsh(pNat, 1)

		//require.Equal(t, pNat.BitLen(), bits)
		//require.Equal(t, qNat.BitLen(), bits-1)
		//require.True(t, pNat.ProbablyPrime(64))
		//require.True(t, qNat.ProbablyPrime(64))
	}
	println(time.Now().String())

	runtime.GC()
}
