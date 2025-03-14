package shamir_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

func Test_MeasureConstantTime_split(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	scheme, err := shamir.NewDealer(3, 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	internal.RunMeasurement(32*8, "shamir_split", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		scheme.Split(secret, crand.Reader)
	})
}

func Test_MeasureConstantTime_combine(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.NewCurve()
	scheme, err := shamir.NewDealer(3, 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var shares []*shamir.Share
	internal.RunMeasurement(32*8, "shamir_combine", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
		shares, err = scheme.Split(secret, crand.Reader)
		require.NoError(t, err)
	}, func() {
		scheme.Combine(shares[0], shares[0], shares[1])
	})
}
