package bf128_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
)

func BenchmarkMul(b *testing.B) {
	prng := crand.Reader
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
	prng := crand.Reader
	field := bf128.NewField()

	z, err := field.Random(prng)
	require.NoError(b, err)
	for range b.N {
		z, _ = z.TryInv()
	}
}
