package lindell17_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func Test_ShouldSplitEdgeCases(t *testing.T) {
	t.Parallel()

	supportedCurves := []*curves.Curve{
		curves.K256(),
		curves.P256(),
		curves.ED25519(),
		curves.BLS12381G1(),
		curves.BLS12381G2(),
	}

	for _, c := range supportedCurves {
		curve := c
		order, err := lindell17.GetCurveOrder(curve)
		oneThird := new(big.Int).Div(new(big.Int).Add(order, big.NewInt(2)), big.NewInt(3))
		twoThird := new(big.Int).Div(new(big.Int).Add(big.NewInt(2), new(big.Int).Mul(order, big.NewInt(2))), big.NewInt(3))

		edgeCases := []*big.Int{
			big.NewInt(0),
			big.NewInt(1),
			big.NewInt(2),
			new(big.Int).Sub(oneThird, big.NewInt(2)),
			new(big.Int).Sub(oneThird, big.NewInt(1)),
			oneThird,
			new(big.Int).Add(oneThird, big.NewInt(1)),
			new(big.Int).Add(oneThird, big.NewInt(2)),
			new(big.Int).Sub(twoThird, big.NewInt(2)),
			new(big.Int).Sub(twoThird, big.NewInt(1)),
			twoThird,
			new(big.Int).Add(twoThird, big.NewInt(1)),
			new(big.Int).Add(twoThird, big.NewInt(2)),
			new(big.Int).Sub(order, big.NewInt(2)),
			new(big.Int).Sub(order, big.NewInt(1)),
			order,
		}

		require.NoError(t, err)
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()

			for _, xInt := range edgeCases {
				x, err := curve.NewScalar().SetBigInt(xInt)
				require.NoError(t, err)

				x1, x2, _, err := lindell17.DecomposeInQThirds(x, crand.Reader)
				require.NoError(t, err)
				require.True(t, lindell17.IsInSecondThird(x1))
				require.True(t, lindell17.IsInSecondThird(x2))
				require.Zero(t, x1.Add(x1).Add(x1).Add(x2).Cmp(x))

				x1, x2, err = lindell17.DecomposeInQThirdsDeterministically(x, crand.Reader)
				require.NoError(t, err)
				require.True(t, lindell17.IsInSecondThird(x1))
				require.True(t, lindell17.IsInSecondThird(x2))
				require.Zero(t, x1.Add(x1).Add(x1).Add(x2).Cmp(x))
			}
		})
	}
}

func Test_ShouldSplit(t *testing.T) {
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

				x1, x2, _, err := lindell17.DecomposeInQThirds(x, crand.Reader)
				require.NoError(t, err)
				require.True(t, lindell17.IsInSecondThird(x1))
				require.True(t, lindell17.IsInSecondThird(x2))
				require.Zero(t, x1.Add(x1).Add(x1).Add(x2).Cmp(x))

				x1, x2, err = lindell17.DecomposeInQThirdsDeterministically(x, crand.Reader)
				require.NoError(t, err)
				require.True(t, lindell17.IsInSecondThird(x1))
				require.True(t, lindell17.IsInSecondThird(x2))
				require.Zero(t, x1.Add(x1).Add(x1).Add(x2).Cmp(x))
			}
		})
	}
}
