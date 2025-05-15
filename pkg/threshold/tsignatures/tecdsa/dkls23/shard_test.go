package dkls23_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
)

func Test_DerivedShardTestVector2(t *testing.T) {
	t.Parallel()

	const TH = 2
	const N = 3
	prng := crand.Reader
	curve := k256.NewCurve()

	chainCodeHex := "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
	chainCodeBytes, err := hex.DecodeString(chainCodeHex)
	require.NoError(t, err)
	chainCode := make([]byte, 32)
	copy(chainCode, chainCodeBytes)

	skHex := "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
	skBytes, err := hex.DecodeString(skHex)
	require.NoError(t, err)
	secretKey, err := curve.ScalarField().Element().SetBytes(skBytes)
	require.NoError(t, err)

	identities, err := ttu.MakeDeterministicTestIdentities(N)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(curve, identities, TH)
	require.NoError(t, err)

	signingKeyShares, partialPublicKeys, err := trusted_dealer.Deal(protocol, secretKey, prng)
	require.NoError(t, err)
	shards := make([]*dkls23.Shard, N)
	for i, id := range identities {
		sks, _ := signingKeyShares.Get(id)
		ppk, _ := partialPublicKeys.Get(id)
		shards[i], err = dkls23.NewShard(protocol, sks, ppk)
		require.NoError(t, err)
	}

	derivedShards := make([]*dkls23.ExtendedShard, N)
	for i, shard := range shards {
		derivedShards[i], err = shard.DeriveWithChainCode(chainCode, 0)
		require.NoError(t, err)
		require.NoError(t, derivedShards[i].Validate(protocol))
	}

	expectedChildSecretKeyHex := "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
	expectedChildPublicKeyHex := "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
	expectedChildChainCodeHex := "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"

	t.Run("child chain code is valid", func(t *testing.T) {
		t.Parallel()
		for _, derivedShard := range derivedShards {
			require.Equal(t, expectedChildChainCodeHex, hex.EncodeToString(derivedShard.ChainCodeBytes))
		}
	})

	t.Run("child public key is valid", func(t *testing.T) {
		t.Parallel()
		for _, derivedShard := range derivedShards {
			require.Equal(t, expectedChildPublicKeyHex, hex.EncodeToString(derivedShard.PublicKey().ToAffineCompressed()))
		}
	})

	t.Run("all child signing key shares interpolate to dlog of public key", func(t *testing.T) {
		t.Parallel()
		ns := make([]int, N)
		for i := range ns {
			ns[i] = i
		}

		sharingConfig := types.DeriveSharingConfig(hashset.NewHashableHashSet(identities...))
		combinations, err := combinatorics.Combinations(ns, TH)
		require.NoError(t, err)
		for _, combination := range combinations {
			shamirShares := make([]*shamir.Share, 0)
			for _, c := range combination {
				sharingId, exists := sharingConfig.Reverse().Get(identities[c])
				require.True(t, exists)

				share := derivedShards[c].SecretShare()
				shamirShares = append(shamirShares, &shamir.Share{
					Id:    sharingId,
					Value: share,
				})
			}

			shamirDealer, err := shamir.NewScheme(TH, N, curve)
			require.NoError(t, err)

			reconstructedPrivateKey, err := shamirDealer.Open(shamirShares...)
			require.NoError(t, err)
			require.Equal(t, expectedChildSecretKeyHex, hex.EncodeToString(reconstructedPrivateKey.Bytes()))

			derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
			aliceShard := derivedShards[0]
			require.True(t, aliceShard.PublicKey().Equal(derivedPublicKey))
		}
	})
}
