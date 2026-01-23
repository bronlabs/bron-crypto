package bf128_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func BenchmarkMul(b *testing.B) {
	prng := pcg.NewRandomised()
	field := bf128.NewField()

	z, err := field.Random(prng)
	require.NoError(b, err)
	x, err := field.Random(prng)
	require.NoError(b, err)
	for range b.N {
		z = z.Mul(x)
	}
}

func BenchmarkInv(b *testing.B) {
	prng := pcg.NewRandomised()
	field := bf128.NewField()

	z, err := field.Random(prng)
	require.NoError(b, err)
	for range b.N {
		z, _ = z.TryInv()
	}
}
