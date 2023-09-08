package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/base/types/integration/testutils"

	"github.com/copperexchange/krypton/pkg/encryptions/paillier"

	"github.com/copperexchange/krypton/pkg/base/curves/k256"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	agreeonrandom_testutils "github.com/copperexchange/krypton/pkg/threshold/agreeonrandom/testutils"
	gennaro_dkg_testutils "github.com/copperexchange/krypton/pkg/threshold/dkg/gennaro/testutils"
	"github.com/copperexchange/krypton/pkg/threshold/sharing/shamir"
	lindell17_dkg_testutils "github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg/testutils"
	"github.com/copperexchange/krypton/pkg/transcripts"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
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

	identities, err := testutils.MakeIdentities(cipherSuite, 3)
	require.NoError(t, err)
	cohortConfig, err := testutils.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, 2, identities)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.ProduceSharedRandomValue(cipherSuite.Curve, identities, crand.Reader)
	require.NoError(t, err)

	gennaroParticipants, err := gennaro_dkg_testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := gennaro_dkg_testutils.DoDkgRound1(gennaroParticipants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Protocol.TotalParties-1)
	}

	r2InsB, r2InsU := gennaro_dkg_testutils.MapDkgRound1OutputsToRound2Inputs(gennaroParticipants, r1OutsB, r1OutsU)
	r2Outs, err := gennaro_dkg_testutils.DoDkgRound2(gennaroParticipants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}
	r3Ins := gennaro_dkg_testutils.MapDkgRound2OutputsToRound3Inputs(gennaroParticipants, r2Outs)
	signingKeyShares, publicKeyShares, err := gennaro_dkg_testutils.DoDkgRound3(gennaroParticipants, r3Ins)
	require.NoError(t, err)

	transcripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		transcripts[i] = hagrid.NewTranscript("Lindell 2017 DKG", nil)
	}

	lindellParticipants, err := lindell17_dkg_testutils.MakeParticipants([]byte("sid"), cohortConfig, identities, signingKeyShares, publicKeyShares, transcripts, nil)
	require.NoError(t, err)

	r1o, err := lindell17_dkg_testutils.DoDkgRound1(lindellParticipants)
	require.NoError(t, err)

	r2i := lindell17_dkg_testutils.MapDkgRound1OutputsToRound2Inputs(lindellParticipants, r1o)
	r2o, err := lindell17_dkg_testutils.DoDkgRound2(lindellParticipants, r2i)
	require.NoError(t, err)

	r3i := lindell17_dkg_testutils.MapDkgRound2OutputsToRound3Inputs(lindellParticipants, r2o)
	r3o, err := lindell17_dkg_testutils.DoDkgRound3(lindellParticipants, r3i)
	require.NoError(t, err)

	r4i := lindell17_dkg_testutils.MapDkgRound3OutputsToRound4Inputs(lindellParticipants, r3o)
	r4o, err := lindell17_dkg_testutils.DoDkgRound4(lindellParticipants, r4i)
	require.NoError(t, err)

	r5i := lindell17_dkg_testutils.MapDkgRound4OutputsToRound5Inputs(lindellParticipants, r4o)
	r5o, err := lindell17_dkg_testutils.DoDkgRound5(lindellParticipants, r5i)
	require.NoError(t, err)

	r6i := lindell17_dkg_testutils.MapDkgRound5OutputsToRound6Inputs(lindellParticipants, r5o)
	r6o, err := lindell17_dkg_testutils.DoDkgRound6(lindellParticipants, r6i)
	require.NoError(t, err)

	r7i := lindell17_dkg_testutils.MapDkgRound6OutputsToRound7Inputs(lindellParticipants, r6o)
	r7o, err := lindell17_dkg_testutils.DoDkgRound7(lindellParticipants, r7i)
	require.NoError(t, err)

	r8i := lindell17_dkg_testutils.MapDkgRound7OutputsToRound8Inputs(lindellParticipants, r7o)
	shards, err := lindell17_dkg_testutils.DoDkgRound8(lindellParticipants, r8i)
	require.NoError(t, err)
	require.NotNil(t, shards)

	t.Run("each transcript recorded common", func(t *testing.T) {
		t.Parallel()
		ok, err := testutils.TranscriptAtSameState("gimme something", transcripts)
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
