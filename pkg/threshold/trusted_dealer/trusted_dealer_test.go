package trusted_dealer_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/trusted_dealer"
)

var (
	//supportedCurves = []curves.Curve{
	//	k256.NewCurve(),
	//	p256.NewCurve(),
	//	edwards25519.NewCurve(),
	//	pasta.NewPallasCurve(),
	//	pasta.NewVestaCurve(),
	//	bls12381.NewG1(),
	//	bls12381.NewG2(),
	//}
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

//Test_TrustedDealer

func testTrustedDealer[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, threshold, n, uint, curve C) {
	t.Helper()

	prng := crand.Reader
	hashFunc := sha256.New

	signingSuite, err := types.NewSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	identities, err := testutils.MakeTestIdentities(t, 3)
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
			//err := value.Validate(thresholdProtocol)
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
					Id:    sharingId,
					Value: signingKeyShare.Share,
				})
			}

			shamirDealer, err := shamir.NewScheme(uint(threshold), uint(n), curve)
			require.NoError(t, err)

			reconstructedPrivateKey, err := shamirDealer.Open(shamirShares...)
			require.NoError(t, err)
			require.True(t, reconstructedPrivateKey.Equal(secret))

			derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
			aliceShard, exists := signingKeyShares.Get(identities[0])
			require.True(t, exists)
			require.True(t, aliceShard.PublicKey.Equal(derivedPublicKey))
		}
	})
}
