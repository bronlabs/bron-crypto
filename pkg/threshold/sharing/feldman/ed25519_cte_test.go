package feldman_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
)

func Test_MeasureConstantTime_split(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	scheme, err := feldman.NewDealer(3, 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	internal.RunMeasurement(32*8, "feldman_split", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		scheme.Split(secret, crand.Reader)
	})
}

func Test_MeasureConstantTime_verify(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	scheme, err := feldman.NewDealer(3, 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var commitments []curves.Point
	var shares []*feldman.Share
	internal.RunMeasurement(32*8, "feldman_verify", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
		commitments, shares, err = scheme.Split(secret, crand.Reader)
		require.NoError(t, err)
	}, func() {
		feldman.Verify(shares[0], commitments)
	})
}

func Test_MeasureConstantTime_combine(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	scheme, err := feldman.NewDealer(3, 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var shares []*feldman.Share
	internal.RunMeasurement(32*8, "feldman_combine", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
		_, shares, err = scheme.Split(secret, crand.Reader)
		require.NoError(t, err)
	}, func() {
		scheme.Combine(shares[0], shares[0], shares[1])
	})
}
