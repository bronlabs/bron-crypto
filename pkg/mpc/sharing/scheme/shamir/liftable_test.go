package shamir_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
)

func TestReconstructInExponent(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	basePoint := curve.PrimeSubGroupGenerator()
	threshold := uint(3)
	total := uint(5)
	shareholders := sharing.NewOrdinalShareholderSet(total)

	ac, err := accessstructures.NewThresholdAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	liftableScheme, err := shamir.NewLiftableScheme(curve, ac)
	require.NoError(t, err)

	out, secret, err := liftableScheme.DealRandom(prng)
	require.NoError(t, err)

	expected := basePoint.ScalarOp(secret.Value())

	// Lift all shares
	liftedShares := make([]*shamir.LiftedShare[*k256.Point, *k256.Scalar], 0, total)
	for _, share := range out.Shares().Values() {
		lifted, err := liftableScheme.LiftShare(share, basePoint)
		require.NoError(t, err)
		liftedShares = append(liftedShares, lifted)
	}

	t.Run("reconstruct from all shares", func(t *testing.T) {
		t.Parallel()

		reconstructed, err := liftableScheme.ReconstructInExponent(liftedShares...)
		require.NoError(t, err)
		require.True(t, reconstructed.Value().Equal(expected))
	})

	t.Run("reconstruct from threshold shares", func(t *testing.T) {
		t.Parallel()

		selectedIDs := []sharing.ID{1, 2, 3}
		selected := make([]*shamir.LiftedShare[*k256.Point, *k256.Scalar], 0, len(selectedIDs))
		for _, id := range selectedIDs {
			share, exists := out.Shares().Get(id)
			require.True(t, exists)
			lifted, err := liftableScheme.LiftShare(share, basePoint)
			require.NoError(t, err)
			selected = append(selected, lifted)
		}

		reconstructed, err := liftableScheme.ReconstructInExponent(selected...)
		require.NoError(t, err)
		require.True(t, reconstructed.Value().Equal(expected))
	})

	t.Run("different threshold sets yield same result", func(t *testing.T) {
		t.Parallel()

		liftShare := func(ids []sharing.ID) []*shamir.LiftedShare[*k256.Point, *k256.Scalar] {
			result := make([]*shamir.LiftedShare[*k256.Point, *k256.Scalar], 0, len(ids))
			for _, id := range ids {
				share, exists := out.Shares().Get(id)
				require.True(t, exists)
				lifted, err := liftableScheme.LiftShare(share, basePoint)
				require.NoError(t, err)
				result = append(result, lifted)
			}
			return result
		}

		r1, err := liftableScheme.ReconstructInExponent(liftShare([]sharing.ID{1, 2, 3})...)
		require.NoError(t, err)

		r2, err := liftableScheme.ReconstructInExponent(liftShare([]sharing.ID{2, 4, 5})...)
		require.NoError(t, err)

		require.True(t, r1.Value().Equal(r2.Value()))
	})

	t.Run("insufficient shares fails", func(t *testing.T) {
		t.Parallel()

		selected := make([]*shamir.LiftedShare[*k256.Point, *k256.Scalar], 0, 2)
		for _, id := range []sharing.ID{1, 2} {
			share, exists := out.Shares().Get(id)
			require.True(t, exists)
			lifted, err := liftableScheme.LiftShare(share, basePoint)
			require.NoError(t, err)
			selected = append(selected, lifted)
		}

		_, err := liftableScheme.ReconstructInExponent(selected...)
		require.Error(t, err)
	})
}
