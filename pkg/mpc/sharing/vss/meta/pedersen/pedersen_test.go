package pedersen_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/pedersen"
)

func newPedersenKey(t *testing.T) *pedcom.Key[*k256.Point, *k256.Scalar] {
	t.Helper()
	curve := k256.NewCurve()
	g := curve.Generator()
	prng := pcg.NewRandomised()
	h, err := curve.Random(prng)
	require.NoError(t, err)
	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(t, err)
	return key
}

func TestPedersenWithShamir(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	prng := pcg.NewRandomised()
	key := newPedersenKey(t)

	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shamirScheme, err := shamir.NewScheme(field, ac)
	require.NoError(t, err)

	scheme, err := pedersen.NewScheme[
		*shamir.Share[*k256.Scalar], *k256.Scalar,
		*shamir.Secret[*k256.Scalar], *k256.Scalar,
		*shamir.DealerOutput[*k256.Scalar],
		*accessstructures.Threshold,
		*shamir.DealerFunc[*k256.Scalar],
		*shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar],
		*shamir.LiftedShare[*k256.Point, *k256.Scalar],
		*k256.Point,
	](
		key,
		shamirScheme,
		shamir.LiftDealerFunc[*k256.Point, *k256.Scalar],
	)
	require.NoError(t, err)

	t.Run("Deal and verify", func(t *testing.T) {
		t.Parallel()
		secret := shamir.NewSecret(field.FromUint64(42))
		dealerOutput, err := scheme.Deal(secret, prng)
		require.NoError(t, err)
		require.NotNil(t, dealerOutput)

		verificationVector := dealerOutput.VerificationVector()

		for _, share := range dealerOutput.Shares().Values() {
			err := scheme.Verify(share, verificationVector)
			require.NoError(t, err, "share %d should verify", share.ID())
		}

		reconstructed, err := scheme.ReconstructAndVerify(
			verificationVector,
			dealerOutput.Shares().Values()...,
		)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("DealRandom and verify", func(t *testing.T) {
		t.Parallel()
		dealerOutput, secret, err := scheme.DealRandom(prng)
		require.NoError(t, err)
		require.NotNil(t, dealerOutput)
		require.NotNil(t, secret)

		verificationVector := dealerOutput.VerificationVector()

		for _, share := range dealerOutput.Shares().Values() {
			err := scheme.Verify(share, verificationVector)
			require.NoError(t, err, "share %d should verify", share.ID())
		}

		reconstructed, err := scheme.ReconstructAndVerify(
			verificationVector,
			dealerOutput.Shares().Values()...,
		)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("Tampered share fails verification", func(t *testing.T) {
		t.Parallel()
		secret := shamir.NewSecret(field.FromUint64(99))
		dealerOutput, err := scheme.Deal(secret, prng)
		require.NoError(t, err)

		verificationVector := dealerOutput.VerificationVector()

		shares := dealerOutput.Shares().Values()
		originalShare := shares[0]

		// Tamper with the secret component
		originalSecret := originalShare.Secret()
		tamperedValue := originalSecret.Value().Add(field.One())
		tamperedSecretShare, err := shamir.NewShare(originalSecret.ID(), tamperedValue, ac)
		require.NoError(t, err)

		tamperedShare, err := pedersen.NewShare(tamperedSecretShare, originalShare.Blinding())
		require.NoError(t, err)

		err = scheme.Verify(tamperedShare, verificationVector)
		require.Error(t, err, "tampered share should fail verification")
	})

	t.Run("Threshold reconstruction", func(t *testing.T) {
		t.Parallel()
		secret := shamir.NewSecret(field.FromUint64(77))
		dealerOutput, err := scheme.Deal(secret, prng)
		require.NoError(t, err)

		verificationVector := dealerOutput.VerificationVector()
		shares := dealerOutput.Shares().Values()

		thresholdShares := shares[:2]
		reconstructed, err := scheme.ReconstructAndVerify(
			verificationVector,
			thresholdShares...,
		)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})
}

func TestPedersenWithISN(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	prng := pcg.NewRandomised()
	key := newPedersenKey(t)

	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	isnScheme, err := isn.NewFiniteScheme[*k256.Scalar](field, ac)
	require.NoError(t, err)

	scheme, err := pedersen.NewScheme[
		*isn.Share[*k256.Scalar], *k256.Scalar,
		*isn.Secret[*k256.Scalar], *k256.Scalar,
		*isn.DealerOutput[*k256.Scalar],
		*accessstructures.CNF,
		isn.DealerFunc[*k256.Scalar],
		isn.LiftedDealerFunc[*k256.Point, *k256.Scalar],
		*isn.LiftedShare[*k256.Point],
		*k256.Point,
	](
		key,
		isnScheme,
		isn.LiftDealerFunc[*k256.Point, *k256.Scalar],
	)
	require.NoError(t, err)

	t.Run("Deal and verify", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(field.FromUint64(42))
		dealerOutput, err := scheme.Deal(secret, prng)
		require.NoError(t, err)
		require.NotNil(t, dealerOutput)

		verificationVector := dealerOutput.VerificationVector()

		for _, share := range dealerOutput.Shares().Values() {
			err := scheme.Verify(share, verificationVector)
			require.NoError(t, err, "share %d should verify", share.ID())
		}

		reconstructed, err := scheme.ReconstructAndVerify(
			verificationVector,
			dealerOutput.Shares().Values()...,
		)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("DealRandom and verify", func(t *testing.T) {
		t.Parallel()
		dealerOutput, secret, err := scheme.DealRandom(prng)
		require.NoError(t, err)
		require.NotNil(t, dealerOutput)
		require.NotNil(t, secret)

		verificationVector := dealerOutput.VerificationVector()

		for _, share := range dealerOutput.Shares().Values() {
			err := scheme.Verify(share, verificationVector)
			require.NoError(t, err, "share %d should verify", share.ID())
		}

		reconstructed, err := scheme.ReconstructAndVerify(
			verificationVector,
			dealerOutput.Shares().Values()...,
		)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})
}
