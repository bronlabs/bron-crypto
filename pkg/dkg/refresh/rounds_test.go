package refresh_test

import (
	crand "crypto/rand"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	gennaro_test_utils "github.com/copperexchange/knox-primitives/pkg/dkg/gennaro/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/dkg/refresh/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

func setup(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) (uniqueSessiondId []byte, identities []integration.IdentityKey, cohortConfig *integration.CohortConfig, dkgSigningKeyShares []*threshold.SigningKeyShare, dkgPublicKeyShares []*threshold.PublicKeyShares) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err = test_utils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities, crand.Reader)
	require.NoError(t, err)

	dkgSigningKeyShares, dkgPublicKeyShares, err = gennaro_test_utils.RunDKG(uniqueSessionId, cohortConfig, identities)
	require.NoError(t, err)

	return uniqueSessionId, identities, cohortConfig, dkgSigningKeyShares, dkgPublicKeyShares
}

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, iterations, threshold, n int) {
	t.Helper()

	uniqueSessionId, identities, cohortConfig, dkgSigningKeyShares, dkgPublicKeyShares := setup(t, curve, h, threshold, n)

	initialSigningKeyShare := dkgSigningKeyShares
	initialPublicKeyShare := dkgPublicKeyShares
	for iteration := 0; iteration < iterations; iteration++ {
		t.Logf("chaing key refresh iteration %d", iteration)
		participants, signingKeyShares, publicKeyShares, err := test_utils.RunRefresh(uniqueSessionId, cohortConfig, identities, initialSigningKeyShare, initialPublicKeyShare)
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
			shamirDealer, err := shamir.NewDealer(threshold, n, curve)
			require.NoError(t, err)
			require.NotNil(t, shamirDealer)
			shamirShares := make([]*shamir.Share, len(participants))
			for i := 0; i < len(participants); i++ {
				shamirShares[i] = &shamir.Share{
					Id:    participants[i].GetSharingId(),
					Value: signingKeyShares[i].Share,
				}
			}

			reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
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

	for _, curve := range []curves.Curve{k256.New()} {
		for _, h := range []func() hash.Hash{sha3.New256} {
			for _, iteration := range []int{1} {
				for _, thresholdConfig := range []struct {
					t int
					n int
				}{
					{t: 2, n: 3},
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
