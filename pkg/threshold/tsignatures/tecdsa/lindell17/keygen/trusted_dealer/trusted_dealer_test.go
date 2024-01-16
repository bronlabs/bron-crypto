package trusted_dealer_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"

	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	h := sha256.New
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}
	th := 2
	n := 3

	identities, err := testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	alice, bob, charlie := identities[0], identities[1], identities[2]

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet([]integration.IdentityKey{alice, bob, charlie}),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.LINDELL17,
			Threshold:            2,
			TotalParties:         3,
			SignatureAggregators: hashset.NewHashSet([]integration.IdentityKey{alice, bob, charlie}),
		},
	}

	shards, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shards)
	require.Len(t, shards, cohortConfig.Protocol.TotalParties)

	t.Run("all signing key shares are valid", func(t *testing.T) {
		t.Parallel()
		for _, shard := range shards {
			err = shard.SigningKeyShare.Validate()
			require.NoError(t, err)
		}
	})

	t.Run("all public keys are the same", func(t *testing.T) {
		t.Parallel()
		publicKeys := map[curves.Point]bool{}
		for _, shard := range shards {
			if _, exists := publicKeys[shard.SigningKeyShare.PublicKey]; !exists {
				publicKeys[shard.SigningKeyShare.PublicKey] = true
			}
		}
		require.Len(t, publicKeys, 1)
	})

	t.Run("all signing key shares interpolate to dlog of public key", func(t *testing.T) {
		t.Parallel()

		shamirDealer, err := shamir.NewDealer(th, n, curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, n)
		for i := 0; i < 3; i++ {
			shamirShares[i] = &shamir.Share{
				Id:    i + 1,
				Value: shards[identities[i].Hash()].SigningKeyShare.Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, shards[identities[0].Hash()].SigningKeyShare.PublicKey.Equal(derivedPublicKey))
	})

	t.Run("all encrypted shares decrypts to correct values", func(t *testing.T) {
		t.Parallel()

		for myAuthKey, myShard := range shards {
			myShare := myShard.SigningKeyShare.Share.Nat()
			myPaillierPrivateKey := myShard.PaillierSecretKey
			for _, theirShard := range shards {
				if myShard.PaillierSecretKey.N.Nat().Eq(theirShard.PaillierSecretKey.N.Nat()) == 0 && myShard.PaillierSecretKey.N2.Nat().Eq(theirShard.PaillierSecretKey.N2.Nat()) == 0 {
					theirEncryptedShare := theirShard.PaillierEncryptedShares[myAuthKey]
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
