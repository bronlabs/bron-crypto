package hjky_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	agreeonrandom_testutils "github.com/bronlabs/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/zero/hjky/testutils"
)

func setup(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) (uniqueSessiondId []byte, identities []types.IdentityKey, protocol types.ThresholdProtocol) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	identities, err = ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err = ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	return uniqueSessionId, identities, protocol
}

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) {
	t.Helper()

	uniqueSessionId, identities, protocol := setup(t, curve, h, threshold, n)

	participants, samples, publicKeySharesMaps, _, err := testutils.RunSample(t, uniqueSessionId, protocol, identities)
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
		shamirDealer, err := shamir.NewDealer(uint(threshold), uint(n), curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(participants))
		for i := 0; i < len(participants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    uint(participants[i].SharingId()),
				Value: samples[i],
			}
		}

		combined, err := shamirDealer.Combine(shamirShares...)
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

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 3},
				{t: 3, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
