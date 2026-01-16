package internal_test

import (
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct/internal"
)

func Benchmark_GCD(b *testing.B) {
	const bits = 4096
	prng := crand.Reader

	boundBig := new(big.Int)
	boundBig.SetBit(boundBig, bits, 1)
	xBig, err := crand.Int(prng, boundBig)
	require.NoError(b, err)
	yBig, err := crand.Int(prng, boundBig)
	require.NoError(b, err)

	x := new(saferith.Nat).SetBig(xBig, bits)
	y := new(saferith.Nat).SetBig(yBig, bits)

	var g saferith.Nat
	b.ResetTimer()
	for range b.N {
		_ = internal.GCD(&g, x, y)
	}
}
