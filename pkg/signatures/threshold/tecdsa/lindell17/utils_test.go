package lindell17_test

import (
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
)

func Test_ShouldSplitEdgeCases(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		k256.New(),
		p256.New(),
		// TODO: reenable when curve order is here
		// edwards25519.New(),
	}

	for _, c := range supportedCurves {
		curve := c
		order := curve.Profile().SubGroupOrder()
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

		t.Run(c.Name(), func(t *testing.T) {
			t.Parallel()

			for _, xInt := range edgeCases {
				x, err := curve.Scalar().SetBigInt(xInt)
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

	supportedCurves := []curves.Curve{
		k256.New(),
		p256.New(),
		// TODO: reenable when curve order is here
		// edwards25519.New(),
	}

	for _, c := range supportedCurves {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			for i := 0; i < n; i++ {
				x := curve.Scalar().Random(crand.Reader)

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
