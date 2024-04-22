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

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	dkls24_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/testutils"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{k256.NewCurve(), edwards25519.NewCurve()} {
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

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	batchSize := ot.Kappa

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)

	participants, shards, err := dkls24_testutils.RunDKG(curve, protocol, identities)
	require.NoError(t, err)
	require.NotNil(t, shards)
	for _, shard := range shards {
		require.NotNil(t, shard.SigningKeyShare)
		require.NotNil(t, shard.PublicKeyShares)
		require.NotNil(t, shard.PairwiseBaseOTs)
		require.Equal(t, shard.PairwiseBaseOTs.Size(), protocol.Participants().Size()-1)
		for pair := range shard.PairwiseBaseOTs.Iter() {
			baseOTConfig := pair.Value
			require.NotNil(t, baseOTConfig)
			require.NotNil(t, baseOTConfig.AsSender)
			require.NotNil(t, baseOTConfig.AsReceiver)
		}
	}
	shardsMap := hashmap.NewHashableHashMap[types.IdentityKey, *dkls23.Shard]()
	for i, shard := range shards {
		shardsMap.Put(identities[i], shard)
	}

	t.Run("each shard is validated", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(shards); i++ {
			err := shards[i].Validate(protocol, identities[i])
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
		shamirDealer, err := shamir.NewDealer(uint(threshold), uint(n), curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(participants))
		for i := 0; i < len(participants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    uint(participants[i].SharingId()),
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

				seedOfIFromJ, exists := shards[i].PairwiseSeeds.Get(participants[j].IdentityKey())
				require.True(t, exists)
				seedOfJFromI, exists := shards[j].PairwiseSeeds.Get(participants[i].IdentityKey())
				require.True(t, exists)
				require.EqualValues(t, seedOfIFromJ, seedOfJFromI)
			}
		}
	})

	t.Run("BaseOT encryption keys match", func(t *testing.T) {
		t.Parallel()
		for _, participant := range participants {
			shard, exists := shardsMap.Get(participant.IdentityKey())
			require.True(t, exists)
			for _, counterPartyIdentity := range shard.PairwiseBaseOTs.Keys() {
				myConfig, exists := shard.PairwiseBaseOTs.Get(counterPartyIdentity)
				require.True(t, exists)
				meAsReceiver := myConfig.AsReceiver
				counterPartyShard, exists := shardsMap.Get(counterPartyIdentity)
				require.True(t, exists)
				counterPartyConfig, exists := counterPartyShard.PairwiseBaseOTs.Get(participant.IdentityKey())
				require.True(t, exists)
				senderCounterParty := counterPartyConfig.AsSender
				for i := 0; i < batchSize; i++ {
					require.Equal(
						t,
						meAsReceiver.ChosenMessages[i],
						senderCounterParty.MessagePairs[i][meAsReceiver.Choices.Get(uint(i))],
					)
				}
				meAsSender := myConfig.AsSender
				receiverCounterParty := counterPartyConfig.AsReceiver
				for i := 0; i < batchSize; i++ {
					require.Equal(
						t,
						receiverCounterParty.ChosenMessages[i],
						meAsSender.MessagePairs[i][receiverCounterParty.Choices.Get(uint(i))],
					)
				}
			}
		}
	})

	t.Run("BaseOT choices match after derandomization", func(t *testing.T) {
		t.Parallel()

		// Transfer messages
		messages := make([][2]ot.Message, batchSize)
		for i := 0; i < batchSize; i++ {
			m0 := sha256.Sum256([]byte(fmt.Sprintf("messages[%d][0]", i)))
			m1 := sha256.Sum256([]byte(fmt.Sprintf("messages[%d][1]", i)))
			messages[i] = [2]ot.Message{
				make([]ot.MessageElement, 1),
				make([]ot.MessageElement, 1),
			}
			messages[i][0][0] = ([ot.KappaBytes]byte)(m0[:ot.KappaBytes])
			messages[i][1][0] = ([ot.KappaBytes]byte)(m1[:ot.KappaBytes])
		}

		for _, participant := range participants {
			shard, exists := shardsMap.Get(participant.IdentityKey())
			require.True(t, exists)
			for _, counterPartyIdentity := range shard.PairwiseBaseOTs.Keys() {
				myConfig, exists := shard.PairwiseBaseOTs.Get(counterPartyIdentity)
				require.True(t, exists)
				meAsReceiver := myConfig.AsReceiver
				counterPartyShard, exists := shardsMap.Get(counterPartyIdentity)
				require.True(t, exists)
				counterPartyConfig, exists := counterPartyShard.PairwiseBaseOTs.Get(participant.IdentityKey())
				require.True(t, exists)
				senderCounterParty := counterPartyConfig.AsSender

				meAsSender := myConfig.AsSender
				receiverCounterParty := counterPartyConfig.AsReceiver

				for _, pair := range []struct {
					Sender   *ot.SenderRotOutput
					Receiver *ot.ReceiverRotOutput
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
						choice := pair.Receiver.Choices.Get(uint(i))
						require.Equal(t, messages[i][choice], decrypted[i])
						require.NotEqual(t, messages[i][1-choice], decrypted[i])
					}
				}
			}
		}
	})

	t.Run("Disaster recovery", func(t *testing.T) {
		for i := 0; i < n-threshold; i++ {
			shardMap := hashmap.NewHashableHashMap[types.IdentityKey, tsignatures.Shard]()
			for j := i; j < i+threshold; j++ {
				shardMap.Put(identities[j], shards[j])
			}
			_, err := tsignatures.ConstructPrivateKey(protocol, shardMap)
			require.NoError(t, err)
		}
	})
}
