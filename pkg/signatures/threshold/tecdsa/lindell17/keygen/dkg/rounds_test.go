package dkg_test

import (
	"crypto/sha256"
	"github.com/copperexchange/knox-primitives/pkg/encryptions/paillier"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	lindell17_dkg_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/keygen/dkg/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Lindell 2017 DKG tests.")
	}
	t.Parallel()
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha256.New,
	}

	identities, err := test_utils.MakeIdentities(cipherSuite, 3)
	require.NoError(t, err)

	transcripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		transcripts[i] = hagrid.NewTranscript("Lindell 2017 DKG")
	}

	signingKeyShares, lindellParticipants, shards, err := lindell17_dkg_test_utils.DoKeygen(cipherSuite, identities, transcripts, 2)

	t.Run("each transcript recorded common", func(t *testing.T) {
		t.Parallel()
		ok, err := test_utils.TranscriptAtSameState("gimme something", transcripts)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("each signing share is different", func(t *testing.T) {
		t.Parallel()

		for i := 0; i < len(shards); i++ {
			for j := i + 1; j < len(shards); j++ {
				require.NotZero(t, shards[i].SigningKeyShare.Share.Cmp(shards[j].SigningKeyShare.Share))
			}
		}
	})

	t.Run("each public key is the same", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(shards); i++ {
			for j := i + 1; j < len(shards); j++ {
				require.True(t, shards[i].SigningKeyShare.PublicKey.Equal(shards[j].SigningKeyShare.PublicKey))
			}
		}
	})

	t.Run("private key matches public key", func(t *testing.T) {
		t.Parallel()

		shamirDealer, err := shamir.NewDealer(2, 3, cipherSuite.Curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(lindellParticipants))
		for i := 0; i < len(lindellParticipants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    lindellParticipants[i].GetSharingId(),
				Value: signingKeyShares[i].Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := cipherSuite.Curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
	})

	t.Run("cKey is encryption of share", func(t *testing.T) {
		for i := 0; i < len(shards); i++ {
			for j := 0; j < len(shards); j++ {
				if i != j {
					myShard := shards[i]
					theirShard := shards[j]
					mySigningShare := myShard.SigningKeyShare.Share
					theirEncryptedSigningShare := theirShard.PaillierEncryptedShares[identities[i].Hash()]
					decryptor, err := paillier.NewDecryptor(myShard.PaillierSecretKey)
					require.NoError(t, err)
					theirDecryptedSigningShareInt, err := decryptor.Decrypt(theirEncryptedSigningShare)
					require.NoError(t, err)
					theirDecryptedSigningShare, err := cipherSuite.Curve.Scalar().SetNat(theirDecryptedSigningShareInt)
					require.NoError(t, err)
					require.Zero(t, mySigningShare.Cmp(theirDecryptedSigningShare))
				}
			}
		}
	})
}
