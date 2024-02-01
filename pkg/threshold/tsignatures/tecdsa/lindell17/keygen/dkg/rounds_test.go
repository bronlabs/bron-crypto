package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	gennaro_dkg_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	lindell17_dkg_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping Lindell 2017 DKG tests.")
	}

	cipherSuite := &integration.CipherSuite{
		Curve: k256.NewCurve(),
		Hash:  sha256.New,
	}

	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)
	cohortConfig, err := testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, 2, identities)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve, identities, crand.Reader)
	require.NoError(t, err)

	gennaroParticipants, err := gennaro_dkg_testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, randomisedFischlin.Name, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := gennaro_dkg_testutils.DoDkgRound1(gennaroParticipants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Protocol.TotalParties-1)
	}

	r2InsB, r2InsU := integration_testutils.MapO2I(gennaroParticipants, r1OutsB, r1OutsU)
	r2Outs, err := gennaro_dkg_testutils.DoDkgRound2(gennaroParticipants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}
	r3Ins := integration_testutils.MapBroadcastO2I(gennaroParticipants, r2Outs)
	signingKeyShares, publicKeyShares, err := gennaro_dkg_testutils.DoDkgRound3(gennaroParticipants, r3Ins)
	require.NoError(t, err)

	xscripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		xscripts[i] = hagrid.NewTranscript("Lindell 2017 DKG", nil)
	}

	lindellParticipants, err := lindell17_dkg_testutils.MakeParticipants([]byte("sid"), cohortConfig, identities, signingKeyShares, publicKeyShares, xscripts, nil)
	require.NoError(t, err)

	r1o, err := lindell17_dkg_testutils.DoDkgRound1(lindellParticipants)
	require.NoError(t, err)

	r2i := integration_testutils.MapBroadcastO2I(lindellParticipants, r1o)
	r2o, err := lindell17_dkg_testutils.DoDkgRound2(lindellParticipants, r2i)
	require.NoError(t, err)

	r3i := integration_testutils.MapBroadcastO2I(lindellParticipants, r2o)
	r3o, err := lindell17_dkg_testutils.DoDkgRound3(lindellParticipants, r3i)
	require.NoError(t, err)

	r4i := integration_testutils.MapBroadcastO2I(lindellParticipants, r3o)
	r4o, err := lindell17_dkg_testutils.DoDkgRound4(lindellParticipants, r4i)
	require.NoError(t, err)

	r5i := integration_testutils.MapUnicastO2I(lindellParticipants, r4o)
	r5o, err := lindell17_dkg_testutils.DoDkgRound5(lindellParticipants, r5i)
	require.NoError(t, err)

	r6i := integration_testutils.MapUnicastO2I(lindellParticipants, r5o)
	r6o, err := lindell17_dkg_testutils.DoDkgRound6(lindellParticipants, r6i)
	require.NoError(t, err)

	r7i := integration_testutils.MapUnicastO2I(lindellParticipants, r6o)
	r7o, err := lindell17_dkg_testutils.DoDkgRound7(lindellParticipants, r7i)
	require.NoError(t, err)

	r8i := integration_testutils.MapUnicastO2I(lindellParticipants, r7o)
	shards, err := lindell17_dkg_testutils.DoDkgRound8(lindellParticipants, r8i)
	require.NoError(t, err)
	require.NotNil(t, shards)

	t.Run("each transcript recorded common", func(t *testing.T) {
		t.Parallel()
		ok, err := testutils.TranscriptAtSameState("gimme something", xscripts)
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
		t.Parallel()
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
					theirDecryptedSigningShare := cipherSuite.Curve.Scalar().SetNat(theirDecryptedSigningShareInt)
					require.Zero(t, mySigningShare.Cmp(theirDecryptedSigningShare))
				}
			}
		}
	})

	t.Run("Disaster recovery", func(t *testing.T) {
		shardMap := make(map[integration.IdentityKey]*tsignatures.SigningKeyShare)
		for i := 0; i < 2; i++ {
			shardMap[identities[i]] = shards[i].SigningKeyShare
		}
		recoveredPrivateKey, err := tsignatures.ConstructPrivateKey(2, 3, cohortConfig.Participants, shardMap)
		require.NoError(t, err)
		recoveredPublicKey := cipherSuite.Curve.ScalarBaseMult(recoveredPrivateKey)
		require.True(t, recoveredPublicKey.Equal(shards[0].SigningKeyShare.PublicKey))
	})
}
