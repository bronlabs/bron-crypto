package feldman_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/meta/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
)

func TestFeldmanWithShamir(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	basePoint := curve.Generator()

	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shamirScheme, err := shamir.NewScheme(field, ac)
	require.NoError(t, err)

	scheme := feldman.NewScheme[
		*shamir.Share[*k256.Scalar], *k256.Scalar, algebra.Numeric,
		*shamir.Secret[*k256.Scalar], *k256.Scalar,
		*shamir.DealerOutput[*k256.Scalar],
		*accessstructures.Threshold,
		*polynomials.Polynomial[*k256.Scalar],
		*testutils.LiftedPoly[*k256.Point, *k256.Scalar, *accessstructures.Threshold],
		*testutils.LiftedEval[*k256.Point],
		*k256.Point,
	](
		basePoint,
		shamirScheme,
		testutils.LiftPolynomialDealerFunc[*k256.Point, *k256.Scalar, *accessstructures.Threshold],
		testutils.LiftShareValue[*k256.Point, *k256.Scalar],
	)

	t.Run("Deal and verify", func(t *testing.T) {
		t.Parallel()
		secret := shamir.NewSecret(field.FromUint64(42))
		dealerOutput, err := scheme.Deal(secret, prng)
		require.NoError(t, err)
		require.NotNil(t, dealerOutput)

		verificationMaterial := dealerOutput.VerificationMaterial()

		// Verify each share
		for _, share := range dealerOutput.Shares().Values() {
			err := scheme.Verify(share, verificationMaterial)
			require.NoError(t, err, "share %d should verify", share.ID())
		}

		// Reconstruct and verify
		reconstructed, err := scheme.ReconstructAndVerify(
			verificationMaterial,
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

		verificationMaterial := dealerOutput.VerificationMaterial()

		// Verify each share
		for _, share := range dealerOutput.Shares().Values() {
			err := scheme.Verify(share, verificationMaterial)
			require.NoError(t, err, "share %d should verify", share.ID())
		}

		// Reconstruct and verify
		reconstructed, err := scheme.ReconstructAndVerify(
			verificationMaterial,
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

		verificationMaterial := dealerOutput.VerificationMaterial()

		// Tamper with a share by creating a new one with a different value
		shares := dealerOutput.Shares().Values()
		originalShare := shares[0]
		tamperedValue := originalShare.Value().Add(field.One())
		tamperedShare, err := shamir.NewShare(originalShare.ID(), tamperedValue, ac)
		require.NoError(t, err)

		err = scheme.Verify(tamperedShare, verificationMaterial)
		require.Error(t, err, "tampered share should fail verification")
	})

	t.Run("Threshold reconstruction", func(t *testing.T) {
		t.Parallel()
		secret := shamir.NewSecret(field.FromUint64(77))
		dealerOutput, err := scheme.Deal(secret, prng)
		require.NoError(t, err)

		verificationMaterial := dealerOutput.VerificationMaterial()
		shares := dealerOutput.Shares().Values()

		// Use only threshold (2) shares to reconstruct
		thresholdShares := shares[:2]
		reconstructed, err := scheme.ReconstructAndVerify(
			verificationMaterial,
			thresholdShares...,
		)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})
}

func TestFeldmanWithISN(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	basePoint := curve.Generator()

	// 2-of-3 threshold as a monotone access structure
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := accessstructures.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	isnScheme, err := isn.NewFiniteScheme[*k256.Scalar](field, ac)
	require.NoError(t, err)

	scheme := feldman.NewScheme[
		*isn.Share[*k256.Scalar], *k256.Scalar, algebra.Numeric,
		*isn.Secret[*k256.Scalar], *k256.Scalar,
		*isn.DealerOutput[*k256.Scalar],
		accessstructures.Monotone,
		isn.DealerFunc[*k256.Scalar],
		*testutils.LiftedISNDealerFunc[*k256.Point, *k256.Scalar, accessstructures.Monotone],
		*testutils.LiftedISNShare[*k256.Point],
		*k256.Point,
	](
		basePoint,
		isnScheme,
		testutils.LiftISNDealerFunc[*k256.Point, *k256.Scalar, accessstructures.Monotone],
		testutils.LiftShareValue[*k256.Point, *k256.Scalar],
	)

	t.Run("Deal and verify", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(field.FromUint64(42))
		dealerOutput, err := scheme.Deal(secret, prng)
		require.NoError(t, err)
		require.NotNil(t, dealerOutput)

		verificationMaterial := dealerOutput.VerificationMaterial()

		for _, share := range dealerOutput.Shares().Values() {
			err := scheme.Verify(share, verificationMaterial)
			require.NoError(t, err, "share %d should verify", share.ID())
		}

		reconstructed, err := scheme.ReconstructAndVerify(
			verificationMaterial,
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

		verificationMaterial := dealerOutput.VerificationMaterial()

		for _, share := range dealerOutput.Shares().Values() {
			err := scheme.Verify(share, verificationMaterial)
			require.NoError(t, err, "share %d should verify", share.ID())
		}

		reconstructed, err := scheme.ReconstructAndVerify(
			verificationMaterial,
			dealerOutput.Shares().Values()...,
		)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})
}
