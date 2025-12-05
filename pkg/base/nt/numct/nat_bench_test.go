package numct_test

import (
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/stretchr/testify/require"
)

func Benchmark_NatGCD(b *testing.B) {
	const bits = 4096
	prng := crand.Reader

	boundBig := new(big.Int)
	boundBig.SetBit(boundBig, bits, 1)
	xBig, err := crand.Int(prng, boundBig)
	require.NoError(b, err)
	yBig, err := crand.Int(prng, boundBig)
	require.NoError(b, err)

	var x, y numct.Nat
	ok := x.SetBytes(xBig.Bytes())
	require.True(b, ok != ct.False)
	ok = y.SetBytes(yBig.Bytes())
	require.True(b, ok != ct.False)

	b.ResetTimer()
	var z numct.Nat
	for range b.N {
		z.GCD(&x, &y)
	}
}
