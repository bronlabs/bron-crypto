package hjky_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/zero/hjky/testutils"
)

var testCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pasta.NewPallasCurve(),
	pasta.NewVestaCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

var testThresholdCfgs = []struct{ th, n uint }{
	{th: 2, n: 2},
	{th: 2, n: 3},
	{th: 3, n: 5},
	{th: 4, n: 6},
	{th: 8, n: 8},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range testCurves {
		for _, thresholdConfig := range testThresholdCfgs {
			t.Run(fmt.Sprintf("curve=%s and t=%d and n=%d", curve.Name(), thresholdConfig.th, thresholdConfig.n), func(t *testing.T) {
				t.Parallel()
				testHappyPath(t, curve, thresholdConfig.th, thresholdConfig.n)
			})
		}
	}
}

func testHappyPath(t *testing.T, curve curves.Curve, threshold, n uint) {
	t.Helper()

	sessionId := []byte("zero share session id")
	identities, err := ttu.MakeDeterministicTestIdentities(int(n))
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(curve, identities, int(threshold))
	require.NoError(t, err)
	tapes := ttu.MakeTranscripts("test tape", identities)

	participants, samples, publicKeySharesMaps, _, err := testutils.DoRun(t, sessionId, protocol, identities, tapes)
	require.NoError(t, err)

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())

	t.Run("none of the samples are zero", func(t *testing.T) {
		t.Parallel()
		for _, sample := range samples {
			require.False(t, sample.IsZero())
		}
	})

	t.Run("samples combine to zero", func(t *testing.T) {
		t.Parallel()
		shamirDealer, err := shamir.NewScheme(threshold, n, curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(participants))
		for i := 0; i < len(participants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    participants[i].SharingId(),
				Value: samples[i],
			}
		}

		combined, err := shamirDealer.Open(shamirShares...)
		require.NoError(t, err)
		require.True(t, combined.IsZero())

	})

	t.Run("public key shares are consistent", func(t *testing.T) {
		t.Parallel()

		for i := range participants {
			for j := range participants {
				sharingId, exists := sharingConfig.Reverse().Get(identities[i])
				require.True(t, exists)
				pk, exists := publicKeySharesMaps[j].Get(sharingId)
				require.True(t, exists)
				require.True(t, curve.ScalarBaseMult(samples[i]).Equal(pk))
			}
		}
	})

}
