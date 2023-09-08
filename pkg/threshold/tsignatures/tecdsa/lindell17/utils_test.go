package lindell17_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/k256"
	"github.com/copperexchange/krypton/pkg/base/curves/p256"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/lindell17"
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
		oneThird := new(saferith.Nat).Div(new(saferith.Nat).Add(order.Nat(), new(saferith.Nat).SetUint64(2), -1), saferith.ModulusFromUint64(3), -1)
		twoThird := new(saferith.Nat).Div(new(saferith.Nat).Add(new(saferith.Nat).SetUint64(2), new(saferith.Nat).Mul(order.Nat(), new(saferith.Nat).SetUint64(2), -1), -1), saferith.ModulusFromUint64(3), -1)

		edgeCases := []*saferith.Nat{
			new(saferith.Nat).SetUint64(0),
			new(saferith.Nat).SetUint64(1),
			new(saferith.Nat).SetUint64(2),
			new(saferith.Nat).Sub(oneThird, new(saferith.Nat).SetUint64(2), -1),
			new(saferith.Nat).Sub(oneThird, new(saferith.Nat).SetUint64(1), -1),
			oneThird,
			new(saferith.Nat).Add(oneThird, new(saferith.Nat).SetUint64(1), -1),
			new(saferith.Nat).Add(oneThird, new(saferith.Nat).SetUint64(2), -1),
			new(saferith.Nat).Sub(twoThird, new(saferith.Nat).SetUint64(2), -1),
			new(saferith.Nat).Sub(twoThird, new(saferith.Nat).SetUint64(1), -1),
			twoThird,
			new(saferith.Nat).Add(twoThird, new(saferith.Nat).SetUint64(1), -1),
			new(saferith.Nat).Add(twoThird, new(saferith.Nat).SetUint64(2), -1),
			new(saferith.Nat).Sub(order.Nat(), new(saferith.Nat).SetUint64(2), -1),
			new(saferith.Nat).Sub(order.Nat(), new(saferith.Nat).SetUint64(1), -1),
			order.Nat(),
		}

		t.Run(c.Name(), func(t *testing.T) {
			t.Parallel()

			for _, xInt := range edgeCases {
				x, err := curve.Scalar().SetNat(xInt)
				require.NoError(t, err)

				x1, x2, err := lindell17.DecomposeInQThirdsDeterministically(x, crand.Reader)
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

				x1, x2, err := lindell17.DecomposeInQThirdsDeterministically(x, crand.Reader)
				require.NoError(t, err)
				require.True(t, lindell17.IsInSecondThird(x1))
				require.True(t, lindell17.IsInSecondThird(x2))
				require.Zero(t, x1.Add(x1).Add(x1).Add(x2).Cmp(x))
			}
		})
	}
}

func Test_Test(t *testing.T) {
	curve := k256.New()
	s := curve.Scalar().One()
	lindell17.DecomposeInQThirdsDeterministically(s, crand.Reader)
}
