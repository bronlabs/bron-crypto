package lindell17_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

// test for x: floor(q/3)*3 <= x < q
func Test_ShouldSplitDegenerativeCases(t *testing.T) {
	t.Parallel()

	supportedCurves := []*curves.Curve{
		curves.K256(),
		curves.P256(),
		curves.ED25519(),
		curves.BLS12381G1(),
		curves.BLS12381G2(),
	}

	for _, curve := range supportedCurves {
		curveBound := curve
		t.Run(curve.Name, func(t *testing.T) {
			t.Parallel()
			x1, err := curveBound.NewScalar().SetBigInt(big.NewInt(-1))
			require.NoError(t, err)
			x2, err := curveBound.NewScalar().SetBigInt(big.NewInt(-2))
			require.NoError(t, err)
			x3, err := curveBound.NewScalar().SetBigInt(big.NewInt(-3))
			require.NoError(t, err)

			_, _, _, err = lindell17.Split(x1, crand.Reader)
			require.NoError(t, err)

			_, _, _, err = lindell17.Split(x2, crand.Reader)
			require.NoError(t, err)

			_, _, _, err = lindell17.Split(x3, crand.Reader)
			require.NoError(t, err)
		})
	}
}

func Test_ShouldSplitDeterministically(t *testing.T) {
	t.Parallel()
	n := 1_000_000
	if testing.Short() {
		n = 10_000
	}

	supportedCurves := []*curves.Curve{
		curves.K256(),
		curves.P256(),
		curves.ED25519(),
		curves.BLS12381G1(),
		curves.BLS12381G2(),
	}

	for _, c := range supportedCurves {
		curve := c
		t.Run(curve.Name, func(t *testing.T) {
			t.Parallel()
			for i := 0; i < n; i++ {
				x := curve.NewScalar().Random(crand.Reader)
				x1, x2, err := lindell17.SplitDeterministically(x, crand.Reader)
				require.NoError(t, err)
				require.True(t, lindell17.IsInSecondThird(x1))
				require.True(t, lindell17.IsInSecondThird(x2))
				require.Zero(t, x1.Add(x1).Add(x1).Add(x2).Cmp(x))
			}
		})
	}
}
