package isn_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
)

func TestReconstructInExponent(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()
	basePoint := curve.PrimeSubGroupGenerator()

	// Maximal unqualified sets: {1,2} and {3,4,5}
	// Qualified sets include any set containing at least one from {1,2} and one from {3,4,5}
	ac, err := accessstructures.NewCNFAccessStructure(
		hashset.NewComparable[sharing.ID](1, 2).Freeze(),
		hashset.NewComparable[sharing.ID](3, 4, 5).Freeze(),
	)
	require.NoError(t, err)

	liftableScheme, err := isn.NewFiniteLiftableScheme[*k256.Point, *k256.Scalar](curve, ac)
	require.NoError(t, err)

	secret := isn.NewSecret(field.FromUint64(42))
	out, err := liftableScheme.Deal(secret, prng)
	require.NoError(t, err)

	expected := basePoint.ScalarOp(secret.Value())

	// Lift all shares
	sharesMap := make(map[sharing.ID]*isn.LiftedShare[*k256.Point])
	for id, share := range out.Shares().Iter() {
		lifted, err := liftableScheme.LiftShare(share, basePoint)
		require.NoError(t, err)
		sharesMap[id] = lifted
	}

	t.Run("reconstruct from minimal qualified set", func(t *testing.T) {
		t.Parallel()

		// {1,3} is qualified: 1 not in {1,2}? No, 1 IS in {1,2}. But 1 is NOT in {3,4,5}, and 3 is NOT in {1,2}.
		reconstructed, err := liftableScheme.ReconstructInExponent(sharesMap[1], sharesMap[3])
		require.NoError(t, err)
		require.True(t, reconstructed.Value().Equal(expected))
	})

	t.Run("reconstruct from all shares", func(t *testing.T) {
		t.Parallel()

		allShares := make([]*isn.LiftedShare[*k256.Point], 0, len(sharesMap))
		for _, share := range sharesMap {
			allShares = append(allShares, share)
		}

		reconstructed, err := liftableScheme.ReconstructInExponent(allShares...)
		require.NoError(t, err)
		require.True(t, reconstructed.Value().Equal(expected))
	})

	t.Run("different qualified sets yield same result", func(t *testing.T) {
		t.Parallel()

		r1, err := liftableScheme.ReconstructInExponent(sharesMap[1], sharesMap[3])
		require.NoError(t, err)

		r2, err := liftableScheme.ReconstructInExponent(sharesMap[2], sharesMap[5])
		require.NoError(t, err)

		require.True(t, r1.Value().Equal(r2.Value()))
	})

	t.Run("unqualified set fails", func(t *testing.T) {
		t.Parallel()

		// {1,2} is a maximal unqualified set — not qualified
		_, err := liftableScheme.ReconstructInExponent(sharesMap[1], sharesMap[2])
		require.Error(t, err)
	})

	t.Run("random secret", func(t *testing.T) {
		t.Parallel()

		out, secret, err := liftableScheme.DealRandom(prng)
		require.NoError(t, err)

		expectedRandom := basePoint.ScalarOp(secret.Value())

		lifted1, err := liftableScheme.LiftShare(mustGet(out.Shares(), 1), basePoint)
		require.NoError(t, err)
		lifted4, err := liftableScheme.LiftShare(mustGet(out.Shares(), 4), basePoint)
		require.NoError(t, err)

		reconstructed, err := liftableScheme.ReconstructInExponent(lifted1, lifted4)
		require.NoError(t, err)
		require.True(t, reconstructed.Value().Equal(expectedRandom))
	})
}

func mustGet[S any](m interface{ Get(sharing.ID) (S, bool) }, id sharing.ID) S {
	v, ok := m.Get(id)
	if !ok {
		panic("share not found")
	}
	return v
}
