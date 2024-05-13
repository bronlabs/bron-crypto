package k256_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Cmp(t *testing.T) {
	prng := crand.Reader

	for i := 0; i < 10_000; i++ {
		x, err := k256.NewScalarField().Random(prng)
		require.NoError(t, err)
		y, err := k256.NewScalarField().Random(prng)
		require.NoError(t, err)

		xNat := x.Nat()
		yNat := y.Nat()

		greater, _, less := xNat.Cmp(yNat)
		if greater != 0 {
			require.True(t, x.Cmp(y) == algebra.GreaterThan)
		} else if less != 0 {
			require.True(t, x.Cmp(y) == algebra.LessThan)
		}
	}
}
