package refresh_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	gennaroTu "github.com/bronlabs/krypton-primitives/pkg/threshold/dkg/gennaro/testutils"
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
	"github.com/bronlabs/krypton-primitives/pkg/threshold/refresh/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
)

func setup(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) (uniqueSessiondId []byte, identities []types.IdentityKey, protocol types.ThresholdProtocol, dkgSigningKeyShares []*tsignatures.SigningKeyShare, dkgPublicKeyShares []*tsignatures.PartialPublicKeys) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	identities, err = ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err = ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	tapes := ttu.MakeTranscripts("testtest", identities)
	dkgSigningKeyShares, dkgPublicKeyShares, err = gennaroTu.DoGennaroDkg(t, uniqueSessionId, protocol, identities, tapes)
	require.NoError(t, err)

	return uniqueSessionId, identities, protocol, dkgSigningKeyShares, dkgPublicKeyShares
}

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, iterations, threshold, n int) {
	t.Helper()

	uniqueSessionId, identities, protocol, dkgSigningKeyShares, dkgPublicKeyShares := setup(t, curve, h, threshold, n)

	initialSigningKeyShare := dkgSigningKeyShares
	initialPublicKeyShare := dkgPublicKeyShares
	for iteration := 0; iteration < iterations; iteration++ {
		t.Logf("chaing key refresh iteration %d", iteration)
		participants, signingKeyShares, publicKeyShares, err := testutils.RunRefresh(t, uniqueSessionId, protocol, identities, initialSigningKeyShare, initialPublicKeyShare)
		require.NoError(t, err)
		require.Len(t, signingKeyShares, len(dkgSigningKeyShares))
		require.Len(t, publicKeyShares, len(dkgPublicKeyShares))

		t.Run("each signing key share is different than all others after the key refresh", func(t *testing.T) {
			t.Parallel()
			for i := 0; i < len(signingKeyShares); i++ {
				for j := i + 1; j < len(signingKeyShares); j++ {
					require.NotZero(t, signingKeyShares[i].Share.Cmp(signingKeyShares[j].Share))
				}
			}
		})
		t.Run("each signing key share is different than the previous one", func(t *testing.T) {
			t.Parallel()
			for i := 0; i < len(signingKeyShares); i++ {
				require.NotZero(t, signingKeyShares[i].Share.Cmp(dkgSigningKeyShares[i].Share))
			}
		})

		t.Run("each public key is the same as all others after the key refresh", func(t *testing.T) {
			t.Parallel()
			for i := 0; i < len(signingKeyShares); i++ {
				for j := i + 1; j < len(signingKeyShares); j++ {
					require.True(t, signingKeyShares[i].PublicKey.Equal(signingKeyShares[j].PublicKey))
				}
			}
		})

		t.Run("each public key is the same as before key refresh", func(t *testing.T) {
			t.Parallel()
			for i := 0; i < len(signingKeyShares); i++ {
				require.True(t, signingKeyShares[i].PublicKey.Equal(dkgSigningKeyShares[i].PublicKey))
			}
		})

		t.Run("reconstructed private key is the dlog of the public key", func(t *testing.T) {
			t.Parallel()
			shamirDealer, err := shamir.NewScheme(uint(threshold), uint(n), curve)
			require.NoError(t, err)
			require.NotNil(t, shamirDealer)
			shamirShares := make([]*shamir.Share, len(participants))
			for i := 0; i < len(participants); i++ {
				shamirShares[i] = &shamir.Share{
					Id:    participants[i].SharingId(),
					Value: signingKeyShares[i].Share,
				}
			}

			reconstructedPrivateKey, err := shamirDealer.Open(shamirShares...)
			require.NoError(t, err)

			derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
			require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
		})

		initialSigningKeyShare = signingKeyShares
		initialPublicKeyShare = publicKeyShares
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, iteration := range []int{1, 5} {
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
					boundedIteration := iteration
					t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d and iteration count=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n, boundedIteration), func(t *testing.T) {
						t.Parallel()
						testHappyPath(t, boundedCurve, boundedHash, boundedIteration, boundedThresholdConfig.t, boundedThresholdConfig.n)
					})
				}
			}
		}
	}
}
