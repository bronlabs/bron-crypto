package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	jf_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	lindell17_dkg_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var cn = randomisedFischlin.Name

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	if os.Getenv("DEFLAKE_TIME_TEST") == "1" {
		t.Skip("Skipping this test in deflake mode.")
	}
	if testing.Short() {
		t.Skip("Skipping Lindell 2017 DKG tests.")
	}

	cipherSuite, err := ttu.MakeSignatureProtocol(k256.NewCurve(), sha256.New)
	require.NoError(t, err)

	threshold := 2
	total := 3

	identities, err := testutils.MakeTestIdentities(cipherSuite, total)
	require.NoError(t, err)
	protocol, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(cipherSuite.Curve(), identities, crand.Reader)
	require.NoError(t, err)

	jf_participants, err := jf_testutils.MakeParticipants(uniqueSessionId, protocol, identities, cn, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := jf_testutils.DoDkgRound1(jf_participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), int(protocol.TotalParties())-1)
	}

	r2InsB, r2InsU := ttu.MapO2I(jf_participants, r1OutsB, r1OutsU)
	r2Outs, err := jf_testutils.DoDkgRound2(jf_participants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}
	r3Ins := ttu.MapBroadcastO2I(jf_participants, r2Outs)
	signingKeyShares, publicKeyShares, err := jf_testutils.DoDkgRound3(jf_participants, r3Ins)
	require.NoError(t, err)

	transcripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		transcripts[i] = hagrid.NewTranscript("Lindell 2017 DKG", nil)
	}

	lindellParticipants, err := lindell17_dkg_testutils.MakeParticipants([]byte("sid"), protocol, identities, signingKeyShares, publicKeyShares, transcripts, nil)
	require.NoError(t, err)

	r1o, err := lindell17_dkg_testutils.DoDkgRound1(lindellParticipants)
	require.NoError(t, err)

	r2i := ttu.MapBroadcastO2I(lindellParticipants, r1o)
	r2o, err := lindell17_dkg_testutils.DoDkgRound2(lindellParticipants, r2i)
	require.NoError(t, err)

	r3i := ttu.MapBroadcastO2I(lindellParticipants, r2o)
	r3o, err := lindell17_dkg_testutils.DoDkgRound3(lindellParticipants, r3i)
	require.NoError(t, err)

	r4i := ttu.MapBroadcastO2I(lindellParticipants, r3o)
	r4o, err := lindell17_dkg_testutils.DoDkgRound4(lindellParticipants, r4i)
	require.NoError(t, err)

	r5i := ttu.MapUnicastO2I(lindellParticipants, r4o)
	r5o, err := lindell17_dkg_testutils.DoDkgRound5(lindellParticipants, r5i)
	require.NoError(t, err)

	r6i := ttu.MapUnicastO2I(lindellParticipants, r5o)
	r6o, err := lindell17_dkg_testutils.DoDkgRound6(lindellParticipants, r6i)
	require.NoError(t, err)

	r7i := ttu.MapUnicastO2I(lindellParticipants, r6o)
	r7o, err := lindell17_dkg_testutils.DoDkgRound7(lindellParticipants, r7i)
	require.NoError(t, err)

	r8i := ttu.MapUnicastO2I(lindellParticipants, r7o)
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

		shamirDealer, err := shamir.NewDealer(2, 3, cipherSuite.Curve())
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(lindellParticipants))
		for i := 0; i < len(lindellParticipants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    uint(lindellParticipants[i].SharingId()),
				Value: signingKeyShares[i].Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := cipherSuite.Curve().ScalarBaseMult(reconstructedPrivateKey)
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
					theirEncryptedSigningShare, exists := theirShard.PaillierEncryptedShares.Get(identities[i])
					require.True(t, exists)
					decryptor, err := paillier.NewDecryptor(myShard.PaillierSecretKey)
					require.NoError(t, err)
					theirDecryptedSigningShareInt, err := decryptor.Decrypt(theirEncryptedSigningShare)
					require.NoError(t, err)
					theirDecryptedSigningShare := cipherSuite.Curve().ScalarField().Element().SetNat(theirDecryptedSigningShareInt)
					require.Zero(t, mySigningShare.Cmp(theirDecryptedSigningShare))
				}
			}
		}
	})

	t.Run("Disaster recovery", func(t *testing.T) {
		shardMap := hashmap.NewHashableHashMap[types.IdentityKey, tsignatures.Shard]()
		for i := 0; i < threshold; i++ {
			shardMap.Put(identities[i], shards[i])
		}
		recoveredPrivateKey, err := tsignatures.ConstructPrivateKey(protocol, shardMap)
		require.NoError(t, err)
		recoveredPublicKey := cipherSuite.Curve().ScalarBaseMult(recoveredPrivateKey)
		require.True(t, recoveredPublicKey.Equal(shards[0].SigningKeyShare.PublicKey))
	})
}
