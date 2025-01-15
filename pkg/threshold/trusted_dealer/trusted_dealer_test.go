package trusted_dealer_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/combinatorics"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pallas"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/trusted_dealer"
)

var (
	supportedCurves = []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
		edwards25519.NewCurve(),
		pallas.NewCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
	configs = []struct{ t, n int }{
		{t: 2, n: 3},
		{t: 3, n: 3},
		{t: 2, n: 5},
		{t: 3, n: 5},
		{t: 5, n: 5},
		{t: 2, n: 11},
		{t: 7, n: 11},
	}
)

func Test_TrustedDealer(t *testing.T) {
	t.Parallel()
	for _, curve := range supportedCurves {
		for _, config := range configs {
			curve := curve
			threshold := config.t
			n := config.n

			t.Run(fmt.Sprintf("%s_t=%d_n=%d", curve.Name(), threshold, n), func(t *testing.T) {
				t.Parallel()

				hashFunc := sha256.New

				signingSuite, err := testutils.MakeSigningSuite(curve, hashFunc)
				require.NoError(t, err)

				identities, err := testutils.MakeTestIdentities(signingSuite, n)
				require.NoError(t, err)

				secret, err := curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)

				thresholdProtocol, err := testutils.MakeThresholdProtocol(curve, identities, threshold)
				require.NoError(t, err)

				signingKeyShares, partialPublicKeys, err := trusted_dealer.Deal(thresholdProtocol, secret, crand.Reader)
				require.NoError(t, err)
				require.NotNil(t, signingKeyShares)
				require.NotNil(t, partialPublicKeys)

				t.Run("all signing key shares are valid", func(t *testing.T) {
					t.Parallel()
					for _, value := range signingKeyShares.Iter() {
						err := value.Validate(thresholdProtocol)
						require.NoError(t, err)
					}
				})

				t.Run("all partial public keys are valid", func(t *testing.T) {
					t.Parallel()
					for _, value := range partialPublicKeys.Iter() {
						err := value.Validate(thresholdProtocol)
						require.NoError(t, err)
					}
				})

				t.Run("all public keys are the same", func(t *testing.T) {
					t.Parallel()
					publicKeys := map[curves.Point]bool{}
					for _, shard := range signingKeyShares.Iter() {
						if _, exists := publicKeys[shard.PublicKey]; !exists {
							publicKeys[shard.PublicKey] = true
						}
					}
					require.Len(t, publicKeys, 1)
				})

				t.Run("all signing key shares interpolate to dlog of public key", func(t *testing.T) {
					t.Parallel()
					N := make([]int, n)
					for i := range n {
						N[i] = i
					}

					sharingConfig := types.DeriveSharingConfig(hashset.NewHashableHashSet(identities...))
					combinations, err := combinatorics.Combinations(N, uint(threshold))
					require.NoError(t, err)
					for _, combination := range combinations {
						shamirShares := make([]*shamir.Share, 0)
						for _, c := range combination {
							sharingId, exists := sharingConfig.Reverse().Get(identities[c])
							require.True(t, exists)

							signingKeyShare, exists := signingKeyShares.Get(identities[c])
							require.True(t, exists)

							shamirShares = append(shamirShares, &shamir.Share{
								Id:    uint(sharingId),
								Value: signingKeyShare.Share,
							})
						}

						shamirDealer, err := shamir.NewDealer(uint(threshold), uint(n), curve)
						require.NoError(t, err)

						reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
						require.NoError(t, err)
						require.True(t, reconstructedPrivateKey.Equal(secret))

						derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
						aliceShard, exists := signingKeyShares.Get(identities[0])
						require.True(t, exists)
						require.True(t, aliceShard.PublicKey.Equal(derivedPublicKey))
					}
				})
			})
		}
	}
}
