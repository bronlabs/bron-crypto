package testutils

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	randomisedFischlin "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17"
	lindell17Dkg "github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

var cn = randomisedFischlin.Name

func MakeParticipants(t require.TestingT, sid []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, signingShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, allTranscripts []transcripts.Transcript, prngs []io.Reader) (participants []*lindell17Dkg.Participant) {
	var err error
	require.Len(t, identities, int(protocol.TotalParties()), "invalid number of identities %d != %d", len(identities), protocol.TotalParties())

	participants = make([]*lindell17Dkg.Participant, protocol.TotalParties())
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}
		var transcript transcripts.Transcript
		if len(allTranscripts) != 0 && allTranscripts[i] != nil {
			transcript = allTranscripts[i]
		}

		if !protocol.Participants().Contains(identity) {
			require.Fail(t, "given test identity not in protocol config (problem in tests?)")
		}
		participants[i], err = lindell17Dkg.NewParticipant(sid, identity.(types.AuthKey), signingShares[i], publicKeyShares[i], protocol, cn, prng, transcript)
		require.NoError(t, err, "could not construct participant")
	}

	return participants
}

func DoDkgRound1(t require.TestingT, participants []*lindell17Dkg.Participant) (round1BroadcastOutputs []*lindell17Dkg.Round1Broadcast) {
	var err error
	round1BroadcastOutputs = make([]*lindell17Dkg.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		require.NoError(t, err, "could not run DKG round 1")
	}

	return round1BroadcastOutputs
}

func DoDkgRound2(t require.TestingT, participants []*lindell17Dkg.Participant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round1Broadcast]) (round2Outputs []*lindell17Dkg.Round2Broadcast) {
	var err error
	round2Outputs = make([]*lindell17Dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i])
		require.NoError(t, err, "could not run DKG round 2")
	}
	return round2Outputs
}

func DoDkgRound3(t require.TestingT, participants []*lindell17Dkg.Participant, round3Inputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round2Broadcast]) (round3Outputs []*lindell17Dkg.Round3Broadcast) {
	var err error
	round3Outputs = make([]*lindell17Dkg.Round3Broadcast, len(participants))
	for i := range participants {
		round3Outputs[i], err = participants[i].Round3(round3Inputs[i])
		require.NoError(t, err, "could not run DKG round 3")
	}
	return round3Outputs
}

func DoDkgRound4(t require.TestingT, participants []*lindell17Dkg.Participant, round4Inputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round3Broadcast]) (round4Unicast []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round4P2P]) {
	var err error
	round4Outputs := make([]network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round4P2P], len(participants))
	for i := range participants {
		round4Outputs[i], err = participants[i].Round4(round4Inputs[i])
		require.NoError(t, err, "could not run DKG round 4")
	}
	return round4Outputs
}

func DoDkgRound5(t require.TestingT, participants []*lindell17Dkg.Participant, round5Inputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round4P2P]) (round5Outputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round5P2P]) {
	var err error
	round5Outputs = make([]network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round5P2P], len(participants))
	for i := range participants {
		round5Outputs[i], err = participants[i].Round5(round5Inputs[i])
		require.NoError(t, err, "could not run DKG round 5")
	}
	return round5Outputs
}

func DoDkgRound6(t require.TestingT, participants []*lindell17Dkg.Participant, round6Inputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round5P2P]) (round6Outputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round6P2P]) {
	var err error
	round6Outputs = make([]network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round6P2P], len(participants))
	for i := range participants {
		round6Outputs[i], err = participants[i].Round6(round6Inputs[i])
		require.NoError(t, err, "could not run DKG round 6")
	}
	return round6Outputs
}

func DoDkgRound7(t require.TestingT, participants []*lindell17Dkg.Participant, round7Inputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round6P2P]) (round7Outputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round7P2P]) {
	var err error
	round7Outputs = make([]network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round7P2P], len(participants))
	for i := range participants {
		round7Outputs[i], err = participants[i].Round7(round7Inputs[i])
		require.NoError(t, err, "could not run DKG round 7")
	}
	return round7Outputs
}

func DoDkgRound8(t require.TestingT, participants []*lindell17Dkg.Participant, round8Inputs []network.RoundMessages[types.ThresholdProtocol, *lindell17Dkg.Round7P2P]) (shards []*lindell17.Shard) {
	var err error
	shards = make([]*lindell17.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round8(round8Inputs[i])
		require.NoError(t, err, "could not run DKG round 8")
	}
	return shards
}

func RunDKG(t *testing.T, sid []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys) (shards []*lindell17.Shard) {
	t.Helper()

	lindellParticipants := MakeParticipants(t, sid, protocol, identities, signingKeyShares, publicKeyShares, nil, nil)
	r1o := DoDkgRound1(t, lindellParticipants)
	r2i := ttu.MapBroadcastO2I(t, lindellParticipants, r1o)
	r2o := DoDkgRound2(t, lindellParticipants, r2i)
	r3i := ttu.MapBroadcastO2I(t, lindellParticipants, r2o)
	r3o := DoDkgRound3(t, lindellParticipants, r3i)
	r4i := ttu.MapBroadcastO2I(t, lindellParticipants, r3o)
	r4o := DoDkgRound4(t, lindellParticipants, r4i)
	r5i := ttu.MapUnicastO2I(t, lindellParticipants, r4o)
	r5o := DoDkgRound5(t, lindellParticipants, r5i)
	r6i := ttu.MapUnicastO2I(t, lindellParticipants, r5o)
	r6o := DoDkgRound6(t, lindellParticipants, r6i)
	r7i := ttu.MapUnicastO2I(t, lindellParticipants, r6o)
	r7o := DoDkgRound7(t, lindellParticipants, r7i)
	r8i := ttu.MapUnicastO2I(t, lindellParticipants, r7o)
	shards = DoDkgRound8(t, lindellParticipants, r8i)
	require.NotNil(t, shards)

	return shards
}
