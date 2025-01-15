package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"os"
	"testing"

	fiatShamir "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/encryptions/paillier"
	agreeonrandomTestUtils "github.com/bronlabs/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	jfTestUtils "github.com/bronlabs/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
	lindell17DkgTestUtils "github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

var cn = fiatShamir.Name

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	if os.Getenv("DEFLAKE_TIME_TEST") == "1" {
		t.Skip("Skipping this test in deflake mode.")
	}

	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha256.New)
	require.NoError(t, err)

	threshold := 2
	total := 3

	identities, err := ttu.MakeTestIdentities(cipherSuite, total)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandomTestUtils.RunAgreeOnRandom(t, cipherSuite.Curve(), identities, crand.Reader)
	require.NoError(t, err)

	jfParticipants, err := jfTestUtils.MakeParticipants(t, uniqueSessionId, protocol, identities, cn, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := jfTestUtils.DoDkgRound1(t, jfParticipants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), int(protocol.TotalParties())-1)
	}

	r2InsB, r2InsU := ttu.MapO2I(t, jfParticipants, r1OutsB, r1OutsU)
	r2Outs, err := jfTestUtils.DoDkgRound2(t, jfParticipants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}
	r3Ins := ttu.MapBroadcastO2I(t, jfParticipants, r2Outs)
	signingKeyShares, publicKeyShares, err := jfTestUtils.DoDkgRound3(t, jfParticipants, r3Ins)
	require.NoError(t, err)

	transcripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		transcripts[i] = hagrid.NewTranscript("Lindell 2017 DKG", nil)
	}

	lindellParticipants := lindell17DkgTestUtils.MakeParticipants(t, []byte("sid"), protocol, identities, signingKeyShares, publicKeyShares, transcripts, nil)
	r1o := lindell17DkgTestUtils.DoDkgRound1(t, lindellParticipants)
	r2i := ttu.MapBroadcastO2I(t, lindellParticipants, r1o)
	r2o := lindell17DkgTestUtils.DoDkgRound2(t, lindellParticipants, r2i)
	r3i := ttu.MapBroadcastO2I(t, lindellParticipants, r2o)
	r3o := lindell17DkgTestUtils.DoDkgRound3(t, lindellParticipants, r3i)
	r4i := ttu.MapBroadcastO2I(t, lindellParticipants, r3o)
	r4o := lindell17DkgTestUtils.DoDkgRound4(t, lindellParticipants, r4i)
	r5i := ttu.MapUnicastO2I(t, lindellParticipants, r4o)
	r5o := lindell17DkgTestUtils.DoDkgRound5(t, lindellParticipants, r5i)
	r6i := ttu.MapUnicastO2I(t, lindellParticipants, r5o)
	r6o := lindell17DkgTestUtils.DoDkgRound6(t, lindellParticipants, r6i)
	r7i := ttu.MapUnicastO2I(t, lindellParticipants, r6o)
	r7o := lindell17DkgTestUtils.DoDkgRound7(t, lindellParticipants, r7i)
	r8i := ttu.MapUnicastO2I(t, lindellParticipants, r7o)
	shards := lindell17DkgTestUtils.DoDkgRound8(t, lindellParticipants, r8i)
	require.NotNil(t, shards)

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())

	t.Run("each transcript recorded common", func(t *testing.T) {
		t.Parallel()
		ok, err := ttu.TranscriptAtSameState("gimme something", transcripts)
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
					theirSharingId, exists := sharingConfig.Reverse().Get(identities[i])
					require.True(t, exists)
					theirEncryptedSigningShare, exists := theirShard.PaillierEncryptedShares.Get(theirSharingId)
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
