package lindell22_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
)

func Test_Bip32DeriveShardTestVector2(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	th := 2
	n := 3

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

	identities, err := testutils.MakeDeterministicTestIdentities(n)
	require.NoError(t, err)
	sort.Sort(types.ByPublicKey(identities))

	protocol, err := testutils.MakeThresholdProtocol(curve, identities, th)
	require.NoError(t, err)

	parentShards, err := trusted_dealer.Deal(protocol, secretKey, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, parentShards)
	require.Equal(t, parentShards.Size(), int(protocol.TotalParties()))

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell22.ExtendedShard]()
	for id, parentShard := range parentShards.Iter() {
		shard, err := parentShard.DeriveWithChainCode(chainCode, 0)
		require.NoError(t, err)
		shards.Put(id, shard)
	}

	expectedChildSecretKeyHex := "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
	expectedChildPublicKeyHex := "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
	expectedChildChainCodeHex := "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"

	t.Run("all chain code are valid", func(t *testing.T) {
		t.Parallel()
		for _, value := range shards.Iter() {
			require.Equal(t, expectedChildChainCodeHex, hex.EncodeToString(value.ChainCodeBytes[:]))
		}
	})

	t.Run("all signing key shares are valid", func(t *testing.T) {
		t.Parallel()
		for _, value := range shards.Iter() {
			err = value.Shard.SigningKeyShare.Validate(protocol)
			require.NoError(t, err)
		}
	})

	t.Run("all partial public keys are valid", func(t *testing.T) {
		t.Parallel()
		for _, value := range shards.Iter() {
			err = value.Shard.PublicKeyShares.Validate(protocol)
			require.NoError(t, err)
			require.Equal(t, expectedChildPublicKeyHex, hex.EncodeToString(value.Shard.PublicKeyShares.PublicKey.ToAffineCompressed()))
		}
	})

	t.Run("all public keys are the same", func(t *testing.T) {
		t.Parallel()
		publicKeys := map[string]bool{}
		for _, value := range shards.Iter() {
			if _, exists := publicKeys[hex.EncodeToString(value.Shard.SigningKeyShare.PublicKey.ToAffineCompressed())]; !exists {
				publicKeys[hex.EncodeToString(value.Shard.SigningKeyShare.PublicKey.ToAffineCompressed())] = true
			}
		}
		require.Len(t, publicKeys, 1)
	})

	t.Run("all signing key shares interpolate to dlog of public key", func(t *testing.T) {
		t.Parallel()

		shamirDealer, err := shamir.NewScheme(uint(th), uint(n), curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, n)
		for i := 0; i < n; i++ {
			thisShard, exists := shards.Get(identities[i])
			require.True(t, exists)
			shamirShares[i] = &shamir.Share{
				Id:    types.SharingID(i + 1),
				Value: thisShard.Shard.SigningKeyShare.Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Open(shamirShares...)
		require.NoError(t, err)
		require.Equal(t, expectedChildSecretKeyHex, hex.EncodeToString(reconstructedPrivateKey.Bytes()))

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		aliceShard, exists := shards.Get(identities[0])
		require.True(t, exists)
		require.True(t, aliceShard.Shard.SigningKeyShare.PublicKey.Equal(derivedPublicKey))
	})
}
