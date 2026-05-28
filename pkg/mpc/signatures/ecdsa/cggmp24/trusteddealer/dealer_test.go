package trusteddealer_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp24/trusteddealer"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

const testKeyLen = 512

func TestDealShards_Threshold2Of3(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	shareholders := ntu.MakeRandomQuorum(t, prng, 3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shards := trusteddealer.DealShardsWithKeyLen(t, curve, prng, accessStructure, testKeyLen)
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
			var shares []*feldman.Share[*k256.Scalar]
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

		refAux := ref.AuxInfo()
		require.NotNil(t, refAux)
		require.Len(t, refAux.PaillierPublicKeys, 3)
		require.Len(t, refAux.RingPedersenPublicKeys, 3)

		for id := range shareholders.Iter() {
			shard := shards[id]
			require.NotNil(t, shard)
			auxInfo := shard.AuxInfo()
			require.NotNil(t, auxInfo)
			require.NotNil(t, auxInfo.PaillierSecretKey)
			require.NotNil(t, auxInfo.RingPedersenSecretKey)

			paillierPublicKey, ok := refAux.PaillierPublicKeys[id]
			require.True(t, ok)
			require.True(t, auxInfo.PaillierSecretKey.Public().Equal(paillierPublicKey), "paillier key mismatch for %d", id)

			ringPedersenPublicKey, ok := refAux.RingPedersenPublicKeys[id]
			require.True(t, ok)
			require.True(t, auxInfo.RingPedersenSecretKey.Export().Equal(ringPedersenPublicKey), "ring pedersen key mismatch for %d", id)

			require.Len(t, auxInfo.PaillierPublicKeys, 3)
			require.Len(t, auxInfo.RingPedersenPublicKeys, 3)
			for otherID := range shareholders.Iter() {
				actualPaillierPublicKey, ok := auxInfo.PaillierPublicKeys[otherID]
				require.True(t, ok)
				expectedPaillierPublicKey, ok := refAux.PaillierPublicKeys[otherID]
				require.True(t, ok)
				require.True(t, actualPaillierPublicKey.Equal(expectedPaillierPublicKey))

				actualRingPedersenPublicKey, ok := auxInfo.RingPedersenPublicKeys[otherID]
				require.True(t, ok)
				expectedRingPedersenPublicKey, ok := refAux.RingPedersenPublicKeys[otherID]
				require.True(t, ok)
				require.True(t, actualRingPedersenPublicKey.Equal(expectedRingPedersenPublicKey))
			}
		}
	})
}
