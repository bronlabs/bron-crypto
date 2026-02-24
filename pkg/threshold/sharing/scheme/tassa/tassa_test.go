package tassa_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/tassa"
)

func TestSchemeHappyPath(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	accessStructure, err := sharing.NewHierarchicalConjunctiveThresholdAccessStructure(
		sharing.WithLevel(2, 1, 2, 3, 4),
		sharing.WithLevel(4, 5, 6, 7, 8),
	)
	require.NoError(t, err)

	field := k256.NewScalarField()
	secretValue, err := field.Random(prng)
	require.NoError(t, err)
	secret := tassa.NewSecret(secretValue)

	scheme, err := tassa.NewScheme(accessStructure, field)
	require.NoError(t, err)
	out, err := scheme.Deal(secret, prng)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, 8, out.Shares().Size())

	// check all possible combinations of shares
	for l1 := range sliceutils.Combinations([]sharing.ID{1, 2, 3, 4}, 2) {
		remaining := hashset.NewComparable[sharing.ID](1, 2, 3, 4, 5, 6, 7, 8).Difference(hashset.NewComparable(l1...))
		for l2 := range sliceutils.KCoveringCombinations(remaining.List(), uint(4-len(l1))) {
			ids := append(l1, l2...)
			require.True(t, accessStructure.IsQualified(ids...))

			subShares := []*tassa.Share[*k256.Scalar]{}
			for _, id := range ids {
				s, ok := out.Shares().Get(id)
				require.True(t, ok)
				subShares = append(subShares, s)
			}

			reconstructed, err := scheme.Reconstruct(subShares...)
			require.NoError(t, err)
			require.NotNil(t, reconstructed)
			require.True(t, secret.Equal(reconstructed))
		}
	}
}

func TestScheme_ShareToAdditiveShare(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	accessStructure, err := sharing.NewHierarchicalConjunctiveThresholdAccessStructure(
		sharing.WithLevel(2, 1, 2, 3, 4),
		sharing.WithLevel(4, 5, 6, 7, 8),
	)
	require.NoError(t, err)

	field := k256.NewScalarField()
	secretValue, err := field.Random(prng)
	require.NoError(t, err)
	secret := tassa.NewSecret(secretValue)

	scheme, err := tassa.NewScheme(accessStructure, field)
	require.NoError(t, err)
	out, err := scheme.Deal(secret, prng)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, 8, out.Shares().Size())

	// check all possible combinations of shares
	for l1 := range sliceutils.Combinations([]sharing.ID{1, 2, 3, 4}, 2) {
		remaining := hashset.NewComparable[sharing.ID](1, 2, 3, 4, 5, 6, 7, 8).Difference(hashset.NewComparable(l1...))
		for l2 := range sliceutils.KCoveringCombinations(remaining.List(), uint(4-len(l1))) {
			ids := append(l1, l2...)
			require.True(t, accessStructure.IsQualified(ids...))
			additiveAccessStructure, err := sharing.NewUnanimityAccessStructure(hashset.NewComparable(ids...).Freeze())
			require.NoError(t, err)

			subShares := []*sharing.AdditiveShare[*k256.Scalar]{}
			for _, id := range ids {
				s, ok := out.Shares().Get(id)
				require.True(t, ok)
				subShare, err := scheme.ShareToAdditiveShare(s, additiveAccessStructure)
				require.NoError(t, err)
				subShares = append(subShares, subShare)
			}

			additiveScheme, err := additive.NewScheme(field, additiveAccessStructure)
			require.NoError(t, err)
			reconstructed, err := additiveScheme.Reconstruct(subShares...)
			require.NoError(t, err)
			require.NotNil(t, reconstructed)
			require.True(t, secret.Value().Equal(reconstructed.Value()))
		}
	}
}

func TestSchemeDealAndReconstructErrors(t *testing.T) {
	t.Parallel()

	accessStructure, err := sharing.NewHierarchicalConjunctiveThresholdAccessStructure(
		sharing.WithLevel(2, 1, 2, 3, 4),
		sharing.WithLevel(4, 5, 6, 7, 8),
	)
	require.NoError(t, err)

	field := k256.NewScalarField()
	scheme, err := tassa.NewScheme(accessStructure, field)
	require.NoError(t, err)
	secret := tassa.NewSecret(field.One())

	t.Run("deal nil secret", func(t *testing.T) {
		t.Parallel()

		out, err := scheme.Deal(nil, pcg.NewRandomised())
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
		require.Nil(t, out)
	})

	t.Run("deal nil prng", func(t *testing.T) {
		t.Parallel()

		out, err := scheme.Deal(secret, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
		require.Nil(t, out)
	})

	t.Run("deal random nil prng", func(t *testing.T) {
		t.Parallel()

		out, generated, err := scheme.DealRandom(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
		require.Nil(t, out)
		require.Nil(t, generated)
	})

	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	share1, exists := out.Shares().Get(1)
	require.True(t, exists)

	t.Run("reconstruct no shares", func(t *testing.T) {
		t.Parallel()

		rec, err := scheme.Reconstruct()
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrArgument)
		require.Nil(t, rec)
	})

	t.Run("reconstruct nil share", func(t *testing.T) {
		t.Parallel()

		rec, err := scheme.Reconstruct(nil)
		require.Error(t, err)
		require.Nil(t, rec)
	})

	t.Run("reconstruct duplicate share ids", func(t *testing.T) {
		t.Parallel()

		rec, err := scheme.Reconstruct(share1, share1)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrMembership)
		require.Nil(t, rec)
	})
}
