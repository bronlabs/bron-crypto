package trusted_dealer_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"

	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	h := sha256.New
	cipherSuite, err := testutils.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)
	th := 2
	n := 3

	identities, err := testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shards)
	require.Equal(t, shards.Size(), int(protocol.TotalParties()))

	t.Run("all signing key shares are valid", func(t *testing.T) {
		t.Parallel()
		for pair := range shards.Iter() {
			err = pair.Value.SigningKeyShare.Validate(protocol)
			require.NoError(t, err)
		}
	})

	t.Run("all public keys are the same", func(t *testing.T) {
		t.Parallel()
		publicKeys := map[curves.Point]bool{}
		for pair := range shards.Iter() {
			if _, exists := publicKeys[pair.Value.SigningKeyShare.PublicKey]; !exists {
				publicKeys[pair.Value.SigningKeyShare.PublicKey] = true
			}
		}
		require.Len(t, publicKeys, 1)
	})

	t.Run("all signing key shares interpolate to dlog of public key", func(t *testing.T) {
		t.Parallel()

		shamirDealer, err := shamir.NewDealer(uint(th), uint(n), curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, n)
		for i := 0; i < n; i++ {
			thisShard, exists := shards.Get(identities[i])
			require.True(t, exists)
			shamirShares[i] = &shamir.Share{
				Id:    uint(i + 1),
				Value: thisShard.SigningKeyShare.Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		aliceShard, exists := shards.Get(identities[0])
		require.True(t, exists)
		require.True(t, aliceShard.SigningKeyShare.PublicKey.Equal(derivedPublicKey))
	})

	t.Run("all encrypted shares decrypts to correct values", func(t *testing.T) {
		t.Parallel()

		for pair := range shards.Iter() {
			myIdentityKey := pair.Key
			myShard := pair.Value
			myShare := myShard.SigningKeyShare.Share.Nat()
			myPaillierPrivateKey := myShard.PaillierSecretKey
			for pair := range shards.Iter() {
				theirShard := pair.Value
				if myShard.PaillierSecretKey.N.Nat().Eq(theirShard.PaillierSecretKey.N.Nat()) == 0 && myShard.PaillierSecretKey.N2.Nat().Eq(theirShard.PaillierSecretKey.N2.Nat()) == 0 {
					theirEncryptedShare, exists := theirShard.PaillierEncryptedShares.Get(myIdentityKey)
					require.True(t, exists)
					decryptor, err := paillier.NewDecryptor(myPaillierPrivateKey)
					require.NoError(t, err)
					theirDecryptedShare, err := decryptor.Decrypt(theirEncryptedShare)
					require.NoError(t, err)
					require.NotZero(t, theirDecryptedShare.Eq(myShare))
				}
			}
		}
	})
}
