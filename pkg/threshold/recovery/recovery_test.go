package recovery_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	feldman_vss "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

func Test_Sanity(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	feldmanScheme, err := feldman_vss.NewScheme(2, 3, curve)
	require.NoError(t, err)

	sk, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)

	dkgShares, dkgVerification, err := feldmanScheme.DealVerifiable(sk, crand.Reader)
	require.NoError(t, err)
	require.Len(t, dkgShares, 3)
	require.Len(t, dkgVerification, 2)

	// bob
	lost := types.SharingID(2)

	// alice
	aliceRandom, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	aliceShares, aliceVerification, err := feldmanScheme.DealVerifiable(aliceRandom, crand.Reader)
	require.NoError(t, err)
	aliceShift := aliceShares[lost].Value
	aliceVerification = feldmanScheme.VerificationSubValue(aliceVerification, aliceShift)
	for i, share := range aliceShares {
		aliceShares[i] = share.SubValue(aliceShift)
		err = feldmanScheme.VerifyShare(aliceShares[i], aliceVerification)
		require.NoError(t, err)
	}

	// charlie
	charlieRandom, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	charlieShares, charlieVerification, err := feldmanScheme.DealVerifiable(charlieRandom, crand.Reader)
	require.NoError(t, err)
	charlieShift := charlieShares[lost].Value
	charlieVerification = feldmanScheme.VerificationSubValue(charlieVerification, charlieShift)
	for i, share := range charlieShares {
		charlieShares[i] = share.SubValue(charlieShift)
		require.NoError(t, err)
		err = feldmanScheme.VerifyShare(charlieShares[i], charlieVerification)
		require.NoError(t, err)
	}

	// bob again
	aliceBlindedShare := feldmanScheme.ShareAdd(dkgShares[1], feldmanScheme.ShareAdd(aliceShares[1], charlieShares[1]))
	charlieBlindedShare := feldmanScheme.ShareAdd(dkgShares[3], feldmanScheme.ShareAdd(aliceShares[3], charlieShares[3]))
	xs := []curves.Scalar{curve.ScalarField().New(1), curve.ScalarField().New(3)}
	ys := []curves.Scalar{aliceBlindedShare.Value, charlieBlindedShare.Value}
	x := lost.ToScalar(curve.ScalarField())
	bobRecoveredShare, err := lagrange.Interpolate(curve, xs, ys, x)
	require.NoError(t, err)

	require.True(t, bobRecoveredShare.Equal(dkgShares[2].Value))
}
