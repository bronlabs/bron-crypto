package trusted_dealer_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/trusted_dealer"
)

var (
	configs = []struct{ t, n uint }{
		{t: 2, n: 3},
		{t: 2, n: 5},
		{t: 3, n: 5},
		{t: 5, n: 5},
		{t: 2, n: 11},
		{t: 7, n: 11},
	}
)

func Test_TrustedDealer(t *testing.T) {
	t.Parallel()

	for _, cfg := range configs {
		t.Run(fmt.Sprintf("t=%d, n=%d", cfg.t, cfg.n), func(t *testing.T) {
			t.Parallel()
			t.Run("curve=k256", func(t *testing.T) {
				t.Parallel()
				testTrustedDealer(t, cfg.t, cfg.n, k256.NewCurve())
			})
			t.Run("curve=p256", func(t *testing.T) {
				t.Parallel()
				testTrustedDealer(t, cfg.t, cfg.n, p256.NewCurve())
			})
			t.Run("curve=edwards25519", func(t *testing.T) {
				t.Parallel()
				testTrustedDealer(t, cfg.t, cfg.n, edwards25519.NewCurve())
			})
			t.Run("curve=pallas", func(t *testing.T) {
				t.Parallel()
				testTrustedDealer(t, cfg.t, cfg.n, pasta.NewPallasCurve())
			})
			t.Run("curve=vesta", func(t *testing.T) {
				t.Parallel()
				testTrustedDealer(t, cfg.t, cfg.n, pasta.NewVestaCurve())
			})
			t.Run("curve=bls12381g1", func(t *testing.T) {
				t.Parallel()
				testTrustedDealer(t, cfg.t, cfg.n, bls12381.NewG1Curve())
			})
			t.Run("curve=bls12381g2", func(t *testing.T) {
				t.Parallel()
				testTrustedDealer(t, cfg.t, cfg.n, bls12381.NewG2Curve())
			})
		})
	}
}

func testTrustedDealer[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, threshold, n uint, curve C) {
	t.Helper()

	prng := crand.Reader
	secret, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)

	identities := testutils.MakeTestIdentities(t, n)
	thresholdProtocol := testutils.MakeThresholdProtocol(t, curve, threshold, identities...)

	signingKeyShares, partialPublicKeys, err := trusted_dealer.Deal(thresholdProtocol, secret, prng)
	require.NoError(t, err)
	require.NotNil(t, signingKeyShares)
	require.NotNil(t, partialPublicKeys)

	//t.Run("all signing key shares are valid", func(t *testing.T) {
	//	t.Parallel()
	//	for _, value := range signingKeyShares.Iter() {
	//		err := value.Validate(thresholdProtocol)
	//		require.NoError(t, err)
	//	}
	//})
	//
	//t.Run("all partial public keys are valid", func(t *testing.T) {
	//	t.Parallel()
	//	for _, value := range partialPublicKeys.Iter() {
	//		err := value.Validate(thresholdProtocol)
	//		require.NoError(t, err)
	//	}
	//})

	t.Run("all public keys are the same", func(t *testing.T) {
		t.Parallel()
		publicKeys := map[curves.Point[P, F, S]]bool{}
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
			N[i] = int(i)
		}

		sharingConfig := types.DeriveSharingConfig(hashset.NewHashableHashSet(identities...))
		combinations := sliceutils.Combinations(N, threshold)
		for combination := range combinations {
			shamirShares := make([]*shamir.Share[S], 0)
			for _, c := range combination {
				sharingId, exists := sharingConfig.Reverse().Get(identities[c])
				require.True(t, exists)

				signingKeyShare, exists := signingKeyShares.Get(identities[c])
				require.True(t, exists)

				shamirShares = append(shamirShares, &shamir.Share[S]{
					Id:    sharingId,
					Value: signingKeyShare.Share,
				})
			}

			shamirDealer, err := shamir.NewScheme(threshold, n, curve.ScalarField())
			require.NoError(t, err)

			reconstructedPrivateKey, err := shamirDealer.Open(shamirShares...)
			require.NoError(t, err)
			require.True(t, reconstructedPrivateKey.Equal(secret))

			derivedPublicKey := curve.Generator().ScalarMul(reconstructedPrivateKey)
			aliceShard, exists := signingKeyShares.Get(identities[0])
			require.True(t, exists)
			require.True(t, aliceShard.PublicKey.Equal(derivedPublicKey))
		}
	})
}
