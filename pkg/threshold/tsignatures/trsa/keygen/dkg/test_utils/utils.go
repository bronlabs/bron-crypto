package test_utils

import (
	nativeRsa "crypto/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func RunDistributedKeyGen(tb testing.TB, primeBitLen uint, prng io.Reader) ([]*trsa.Shard, *nativeRsa.PublicKey) {
	identities, err := testutils.MakeDeterministicTestIdentities(3)
	require.NoError(tb, err)
	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, 2)
	require.NoError(tb, err)
	var sessionId [128 / 8]byte
	_, err = io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	participants := make([]*dkg.Participant, 3)
	for i := range participants {
		tape := hagrid.NewTranscript("TEST", nil)
		tape.AppendMessages("sessionId", sessionId[:])
		participants[i] = dkg.NewParticipant(tape, identities[i], protocol, primeBitLen, prng)
	}

	i := uint64(0)
mainLoop:
	for {
		i += 1

		r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P], len(participants))
		for i, participant := range participants {
			r1Out[i] = participant.Round1()
		}
		r2In := testutils.MapUnicastO2I(tb, participants, r1Out)

		r2Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round2P2P], len(participants))
		for i, participant := range participants {
			r2Out[i] = participant.Round2(r2In[i])
		}
		r3In := testutils.MapUnicastO2I(tb, participants, r2Out)

		r3Out := make([]*dkg.Round3Broadcast, len(participants))
		for i, participant := range participants {
			r3Out[i] = participant.Round3(r3In[i])
		}
		r4In := testutils.MapBroadcastO2I(tb, participants, r3Out)

		r4Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round4P2P], len(participants))
		oks := make([]bool, len(participants))
		for i, participant := range participants {
			r4Out[i], oks[i] = participant.Round4(r4In[i])
		}
		if !oks[0] {
			continue mainLoop
		}
		r5In := testutils.MapUnicastO2I(tb, participants, r4Out)

		r5Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round5P2P], len(participants))
		for i, participant := range participants {
			r5Out[i] = participant.Round5(r5In[i])
		}
		r6In := testutils.MapUnicastO2I(tb, participants, r5Out)

		r6Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round6P2P], len(participants))
		for i, participant := range participants {
			r6Out[i] = participant.Round6(r6In[i])
		}
		r7In := testutils.MapUnicastO2I(tb, participants, r6Out)

		r7Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round7P2P], len(participants))
		for i, participant := range participants {
			r7Out[i] = participant.Round7(r7In[i])
		}
		r8In := testutils.MapUnicastO2I(tb, participants, r7Out)

		r8Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round8P2P], len(participants))
		for i, participant := range participants {
			r8Out[i] = participant.Round8(r8In[i])
		}
		r9In := testutils.MapUnicastO2I(tb, participants, r8Out)

		r9Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round9P2P], len(participants))
		for i, participant := range participants {
			r9Out[i] = participant.Round9(r9In[i])
		}
		r10In := testutils.MapUnicastO2I(tb, participants, r9Out)

		r10Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round10P2P], len(participants))
		for i, participant := range participants {
			r10Out[i] = participant.Round10(r10In[i])
		}
		r11In := testutils.MapUnicastO2I(tb, participants, r10Out)

		r11Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round11P2P], len(participants))
		for i, participant := range participants {
			r11Out[i] = participant.Round11(r11In[i])
		}
		r12In := testutils.MapUnicastO2I(tb, participants, r11Out)

		r12Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round12P2P], len(participants))
		for i, participant := range participants {
			r12Out[i] = participant.Round12(r12In[i])
		}
		r13In := testutils.MapUnicastO2I(tb, participants, r12Out)

		r13Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round13P2P], len(participants))
		for i, participant := range participants {
			r13Out[i] = participant.Round13(r13In[i])
		}
		r14In := testutils.MapUnicastO2I(tb, participants, r13Out)

		r14Out := make([]*dkg.Round14Broadcast, len(participants))
		for i, participant := range participants {
			r14Out[i] = participant.Round14(r14In[i])
		}
		r15In := testutils.MapBroadcastO2I(tb, participants, r14Out)

		oks = make([]bool, len(participants))
		for i, participant := range participants {
			oks[i] = participant.Round15(r15In[i])
		}
		require.Equal(tb, oks[0], oks[1])
		require.Equal(tb, oks[0], oks[2])
		if !oks[0] {
			continue mainLoop
		}

	shareLoop:
		for {
			r16Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round16P2P], 3)
			for i, participant := range participants {
				r16Out[i] = participant.Round16()
			}
			r17In := testutils.MapUnicastO2I(tb, participants, r16Out)

			r17Out := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round17P2P], 3)
			for i, participant := range participants {
				r17Out[i] = participant.Round17(r17In[i])
			}
			r18In := testutils.MapUnicastO2I(tb, participants, r17Out)

			r18Out := make([]*dkg.Round18Broadcast, 3)
			for i, participant := range participants {
				r18Out[i] = participant.Round18(r18In[i])
			}
			r19In := testutils.MapBroadcastO2I(tb, participants, r18Out)

			shards := make([]*trsa.Shard, 3)
			pks := make([]*nativeRsa.PublicKey, 3)
			for i, participant := range participants {
				shards[i], pks[i], oks[i] = participant.Round19(r19In[i])
			}
			require.Equal(tb, oks[0], oks[1])
			require.Equal(tb, oks[0], oks[2])
			if !oks[0] {
				continue shareLoop
			}

			println(i)
			return shards, pks[0]
		}
	}
}
