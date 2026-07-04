package trusteddealer_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21/keygen/trusteddealer"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const testKeyLen = 2048

func TestDealShards_Threshold2Of3(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testDealShardsThreshold2Of3(t, k256.NewCurve())
	})

	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testDealShardsThreshold2Of3(t, p256.NewCurve())
	})
}

func testDealShardsThreshold2Of3[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, curve sigecdsa.Curve[P, B, S]) {
	t.Helper()

	prng := crand.Reader
	shareholders := ntu.MakeRandomQuorum(t, prng, 3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shards, err := trusteddealer.Deal(curve, accessStructure, testKeyLen, prng)
	require.NoError(t, err)
	require.Len(t, shards, 3)

	ref := shards[shareholders.List()[0]]
	require.NotNil(t, ref)
	publicKeyValue := ref.PublicKeyValue()
	verificationVector := ref.VerificationVector()

	t.Run("public key matches secret shares", func(t *testing.T) {
		t.Parallel()

		feldmanScheme, err := feldman.NewScheme(curve, accessStructure)
		require.NoError(t, err)

		for id := range shareholders.Iter() {
			shard := shards[id]
			require.NotNil(t, shard)
			require.True(t, publicKeyValue.Equal(shard.PublicKeyValue()))

			publicKeyShare, ok := shard.PublicKeyShares().Get(id)
			require.True(t, ok)
			liftedShare, err := feldman.LiftShare(shard.Share(), curve.Generator())
			require.NoError(t, err)
			require.True(t, liftedShare.Equal(publicKeyShare), "share %d does not match its public key share", id)
		}

		for ids := range sliceutils.KCoveringCombinations(shareholders.List(), 2) {
			var shares []*feldman.Share[S]
			for _, id := range ids {
				shares = append(shares, shards[id].Share())
			}
			secret, err := feldmanScheme.ReconstructAndVerify(verificationVector, shares...)
			require.NoError(t, err)
			require.True(t, curve.ScalarBaseOp(secret.Value()).Equal(publicKeyValue), "quorum reconstructs the wrong public key")
		}
	})

	t.Run("auxiliary public keys match secret keys", func(t *testing.T) {
		t.Parallel()

		for id := range shareholders.Iter() {
			shard := shards[id]
			require.NotNil(t, shard)
			auxInfo := shard.AuxInfo()
			require.NotNil(t, auxInfo)
			paillierSecretKey := shard.AuxInfo().PaillierSecretKey()
			require.NotNil(t, paillierSecretKey)
			ringPedersenSecretKey := shard.AuxInfo().RingPedersenSecretKey()
			require.NotNil(t, ringPedersenSecretKey)

			for otherID := range shareholders.Iter() {
				if otherID == id {
					continue
				}

				require.Len(t, shards[otherID].AuxInfo().PaillierPublicKeys(), shareholders.Size()-1)
				require.Len(t, shards[otherID].AuxInfo().RingPedersenPublicKeys(), shareholders.Size()-1)

				actualPaillierPublicKey := shards[otherID].AuxInfo().PaillierPublicKeys()[id]
				expectedPaillierPublicKey := paillierSecretKey.Public()
				require.True(t, actualPaillierPublicKey.Equal(expectedPaillierPublicKey))

				actualRingPedersenPublicKey := shards[otherID].AuxInfo().RingPedersenPublicKeys()[id]
				expectedRingPedersenPublicKey := ringPedersenSecretKey.Export()
				require.True(t, actualRingPedersenPublicKey.Equal(expectedRingPedersenPublicKey))
			}
		}
	})

	t.Run("refresh id matches", func(t *testing.T) {
		t.Parallel()

		for id := range shareholders.Iter() {
			for otherID := range shareholders.Iter() {
				require.Equal(t, shards[id].RefreshID(), shards[otherID].RefreshID())
			}
		}
	})
}
