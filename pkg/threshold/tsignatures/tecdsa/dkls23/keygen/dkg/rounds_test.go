package dkg_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton/pkg/base/types/integration/testutils"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/copperexchange/krypton/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23"
	dkls23_testutils "github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23/keygen/dkg/testutils"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23/testutils"

	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/curves/k256"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton/pkg/ot/extension/softspoken"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	batchSize := softspoken.Kappa
	identities, cohortConfig, participants, shards, err := dkls23_testutils.KeyGen(curve, h, threshold, n, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, shards)
	for _, shard := range shards {
		require.NotNil(t, shard.SigningKeyShare)
		require.NotNil(t, shard.PublicKeyShares)
		require.NotNil(t, shard.PairwiseSeeds)
		require.Len(t, shard.PairwiseSeeds, cohortConfig.Participants.Len()-1)
		require.NotNil(t, shard.PairwiseBaseOTs)
		require.Len(t, shard.PairwiseBaseOTs, cohortConfig.Participants.Len()-1)
		for _, baseOTConfig := range shard.PairwiseBaseOTs {
			require.NotNil(t, baseOTConfig)
			require.NotNil(t, baseOTConfig.AsSender)
			require.NotNil(t, baseOTConfig.AsReceiver)
		}
	}
	shardsMap := make(map[types.IdentityHash]*dkls23.Shard, len(shards))
	for i, shard := range shards {
		shardsMap[identities[i].Hash()] = shard
	}

	t.Run("each shard is validated", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(shards); i++ {
			err := shards[i].Validate(cohortConfig)
			require.NoError(t, err)
		}
	})

	t.Run("each signing share is different", func(t *testing.T) {
		t.Parallel()
		// each signing share is different
		for i := 0; i < len(shards); i++ {
			for j := i + 1; j < len(shards); j++ {
				require.NotZero(t, shards[i].SigningKeyShare.Share.Cmp(shards[j].SigningKeyShare.Share))
			}
		}
	})

	t.Run("each public key is the same", func(t *testing.T) {
		t.Parallel()
		// each public key is the same
		for i := 0; i < len(shards); i++ {
			for j := i + 1; j < len(shards); j++ {
				require.True(t, shards[i].SigningKeyShare.PublicKey.Equal(shards[j].SigningKeyShare.PublicKey))
			}
		}
	})

	t.Run("reconstructed public key is the same as a party's public key", func(t *testing.T) {
		t.Parallel()
		shamirDealer, err := shamir.NewDealer(threshold, n, curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(participants))
		for i := 0; i < len(participants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    participants[i].GetSharingId(),
				Value: shards[i].SigningKeyShare.Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, shards[0].SigningKeyShare.PublicKey.Equal(derivedPublicKey))
	})

	t.Run("each pair of seeds for all parties match", func(t *testing.T) {
		t.Parallel()
		for i := range participants {
			for j := range participants {
				if i == j {
					continue
				}
				seedOfIFromJ := shards[i].PairwiseSeeds[participants[j].GetIdentityKey().Hash()]
				seedOfJFromI := shards[j].PairwiseSeeds[participants[i].GetIdentityKey().Hash()]
				require.EqualValues(t, seedOfIFromJ, seedOfJFromI)
			}
		}
	})

	t.Run("BaseOT encryption keys match", func(t *testing.T) {
		t.Parallel()
		for _, participant := range participants {
			shard := shardsMap[participant.MyIdentityKey.Hash()]
			for counterPartyIdentity, myConfig := range shard.PairwiseBaseOTs {
				meAsReceiver := myConfig.AsReceiver
				senderCounterParty := shardsMap[counterPartyIdentity].PairwiseBaseOTs[participant.MyIdentityKey.Hash()].AsSender
				for i := 0; i < batchSize; i++ {
					require.Equal(
						t,
						meAsReceiver.OneTimePadDecryptionKey[i],
						senderCounterParty.OneTimePadEncryptionKeys[i][myConfig.AsReceiver.RandomChoiceBits[i]],
					)
				}
				meAsSender := myConfig.AsSender
				receiverCounterParty := shardsMap[counterPartyIdentity].PairwiseBaseOTs[participant.MyIdentityKey.Hash()].AsReceiver
				for i := 0; i < batchSize; i++ {
					require.Equal(
						t,
						receiverCounterParty.OneTimePadDecryptionKey[i],
						meAsSender.OneTimePadEncryptionKeys[i][receiverCounterParty.RandomChoiceBits[i]],
					)
				}
			}
		}
	})

	t.Run("BaseOT choices match after derandomization", func(t *testing.T) {
		t.Parallel()

		// Transfer messages
		messages := make([][2][32]byte, batchSize)
		for i := 0; i < batchSize; i++ {
			messages[i] = [2][32]byte{
				sha256.Sum256([]byte(fmt.Sprintf("message[%d][0]", i))),
				sha256.Sum256([]byte(fmt.Sprintf("message[%d][1]", i))),
			}
		}

		for _, participant := range participants {
			shard := shardsMap[participant.MyIdentityKey.Hash()]
			for counterPartyIdentity, myConfig := range shard.PairwiseBaseOTs {
				meAsReceiver := myConfig.AsReceiver
				senderCounterParty := shardsMap[counterPartyIdentity].PairwiseBaseOTs[participant.MyIdentityKey.Hash()].AsSender

				meAsSender := myConfig.AsSender
				receiverCounterParty := shardsMap[counterPartyIdentity].PairwiseBaseOTs[participant.MyIdentityKey.Hash()].AsReceiver

				for _, pair := range []struct {
					Sender   *vsot.SenderOutput
					Receiver *vsot.ReceiverOutput
				}{
					{
						Sender:   senderCounterParty,
						Receiver: meAsReceiver,
					},
					{
						Sender:   meAsSender,
						Receiver: receiverCounterParty,
					},
				} {
					ciphertexts, err := pair.Sender.Encrypt(messages)
					require.NoError(t, err)
					decrypted, err := pair.Receiver.Decrypt(ciphertexts)
					require.NoError(t, err)
					for i := 0; i < batchSize; i++ {
						choice := pair.Receiver.RandomChoiceBits[i]
						require.Equal(t, messages[i][choice], decrypted[i])
						require.NotEqual(t, messages[i][1-choice], decrypted[i])
					}
				}
			}
		}
	})
}

func testInvalidSid(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := testutils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocols.DKLS23, identities, threshold, identities)
	require.NoError(t, err)

	participants, err := testutils.MakeDkgParticipants(curve, cohortConfig, identities, nil, nil)
	participants[0].ZeroSamplingParty.UniqueSessionId = []byte("invalid sid")
	participants[0].GennaroParty.UniqueSessionId = []byte("invalid sid")
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Protocol.TotalParties-1)
	}

	r2InsB, r2InsU := testutils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2OutsB, r2OutsU, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)

	r3InsB, r3InsU := testutils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	_, err = testutils.DoDkgRound3(participants, r3InsB, r3InsU)
	require.Error(t, err)
	require.True(t, errs.IsIdentifiableAbort(err, nil))
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{k256.New(), edwards25519.New()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 2},
				{t: 2, n: 3},
				{t: 3, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestInvalidSid(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{k256.New(), edwards25519.New()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 2},
				{t: 2, n: 3},
				{t: 3, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testInvalidSid(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
