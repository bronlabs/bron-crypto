package lindell17_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/lindell17"
)

func TestDecomposeTwoThirds(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	prng := pcg.New(1, 2)

	for _, x := range []*k256.Scalar{
		field.Zero(),
		field.One(),
		field.FromUint64(42),
		field.FromUint64(123456789),
	} {
		xPrime, xDoublePrime, err := lindell17.DecomposeTwoThirds(x, prng)
		require.NoError(t, err)
		require.True(t, xPrime.Add(xPrime).Add(xPrime).Add(xDoublePrime).Equal(x))
	}
}
