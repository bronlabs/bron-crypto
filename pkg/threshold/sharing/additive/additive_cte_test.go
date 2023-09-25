package additive_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/additive"
)

func Test_MeasureConstantTime_split(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	curve := k256.New()
	dealer, err := additive.NewDealer(5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	internal.RunMeasurement(32*8, "additive_sharing_split", func(i int) {
		secret = curve.Scalar().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
	}, func() {
		dealer.Split(secret, crand.Reader)
	})
}

func Test_MeasureConstantTime_combine(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	curve := k256.New()
	dealer, err := additive.NewDealer(5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var shares []*additive.Share
	internal.RunMeasurement(32*8, "additive_sharing_combine", func(i int) {
		secret = curve.Scalar().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		shares, err = dealer.Split(secret, crand.Reader)
		require.NoError(t, err)
	}, func() {
		dealer.Combine(shares)
	})
}
