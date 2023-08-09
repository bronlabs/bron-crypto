package dkg_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/ot/extension/softspoken"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func testHappyPath(t *testing.T, curve *curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	batchSize := softspoken.Kappa

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.DKLS23, identities, threshold, identities)
	require.NoError(t, err)

	participants, err := test_utils.MakeParticipants(curve, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2OutsB, r2OutsU, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r3InsB, r3InsU := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	r3OutsU, err := test_utils.DoDkgRound3(participants, r3InsB, r3InsU)
	require.NoError(t, err)
	for _, out := range r3OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r4InsU := test_utils.MapDkgRound3OutputsToRound4Inputs(participants, r3OutsU)
	r4OutsU, err := test_utils.DoDkgRound4(participants, r4InsU)
	require.NoError(t, err)
	for _, out := range r4OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r5InsU := test_utils.MapDkgRound4OutputsToRound5Inputs(participants, r4OutsU)
	r5OutsU, err := test_utils.DoDkgRound5(participants, r5InsU)
	require.NoError(t, err)
	for _, out := range r5OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r6InsU := test_utils.MapDkgRound5OutputsToRound6Inputs(participants, r5OutsU)
	shards, err := test_utils.DoDkgRound6(participants, r6InsU)
	require.NoError(t, err)
	require.NotNil(t, shards)
	for _, shard := range shards {
		require.NotNil(t, shard.SigningKeyShare)
		require.NotNil(t, shard.PublicKeyShares)
		require.NotNil(t, shard.PairwiseSeeds)
		require.Len(t, shard.PairwiseSeeds, len(cohortConfig.Participants)-1)
		require.NotNil(t, shard.PairwiseBaseOTs)
		require.Len(t, shard.PairwiseBaseOTs, len(cohortConfig.Participants)-1)
		for _, baseOTConfig := range shard.PairwiseBaseOTs {
			require.NotNil(t, baseOTConfig)
			require.NotNil(t, baseOTConfig.AsSender)
			require.NotNil(t, baseOTConfig.AsReceiver)
		}
	}
	shardsMap := make(map[integration.IdentityKey]*dkls23.Shard, len(shards))
	for i, shard := range shards {
		shardsMap[identities[i]] = shard
	}

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
				seedOfIFromJ := shards[i].PairwiseSeeds[participants[j].GetIdentityKey()]
				seedOfJFromI := shards[j].PairwiseSeeds[participants[i].GetIdentityKey()]
				require.EqualValues(t, seedOfIFromJ, seedOfJFromI)
			}
		}
	})

	t.Run("BaseOT encryption keys match", func(t *testing.T) {
		t.Parallel()
		for _, participant := range participants {
			shard := shardsMap[participant.MyIdentityKey]
			for counterPartyIdentity, myConfig := range shard.PairwiseBaseOTs {
				meAsReceiver := myConfig.AsReceiver
				senderCounterParty := shardsMap[counterPartyIdentity].PairwiseBaseOTs[participant.MyIdentityKey].AsSender
				for i := 0; i < batchSize; i++ {
					require.Equal(
						t,
						meAsReceiver.OneTimePadDecryptionKey[i],
						senderCounterParty.OneTimePadEncryptionKeys[i][myConfig.AsReceiver.RandomChoiceBits[i]],
					)
				}
				meAsSender := myConfig.AsSender
				receiverCounterParty := shardsMap[counterPartyIdentity].PairwiseBaseOTs[participant.MyIdentityKey].AsReceiver
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
			shard := shardsMap[participant.MyIdentityKey]
			for counterPartyIdentity, myConfig := range shard.PairwiseBaseOTs {
				meAsReceiver := myConfig.AsReceiver
				senderCounterParty := shardsMap[counterPartyIdentity].PairwiseBaseOTs[participant.MyIdentityKey].AsSender

				meAsSender := myConfig.AsSender
				receiverCounterParty := shardsMap[counterPartyIdentity].PairwiseBaseOTs[participant.MyIdentityKey].AsReceiver

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

func testInvalidSid(t *testing.T, curve *curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.DKLS23, identities, threshold, identities)
	require.NoError(t, err)

	participants, err := test_utils.MakeParticipants(curve, cohortConfig, identities, nil)
	participants[0].ZeroSamplingParty.UniqueSessionId = []byte("invalid sid")
	participants[0].GennaroParty.UniqueSessionId = []byte("invalid sid")
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2OutsB, r2OutsU, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)

	r3InsB, r3InsU := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	_, err = test_utils.DoDkgRound3(participants, r3InsB, r3InsU)
	require.Error(t, err)
	require.True(t, errs.IsIdentifiableAbort(err))
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.K256(), curves.ED25519()} {
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
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestInvalidSid(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.K256(), curves.ED25519()} {
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
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testInvalidSid(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
