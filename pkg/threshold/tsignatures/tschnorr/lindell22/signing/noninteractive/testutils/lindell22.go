package testutils

import (
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22"
	noninteractive_signing "github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/signing/noninteractive"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const cn = fischlin.Name

func MakePreGenParticipants(t require.TestingT, identities []types.IdentityKey, sid []byte, protocol types.ThresholdProtocol, myTranscripts []transcripts.Transcript) (participants []*noninteractive_signing.PreGenParticipant) {
	var err error
	prng := crand.Reader
	parties := make([]*noninteractive_signing.PreGenParticipant, len(identities))
	for i := range identities {
		parties[i], err = noninteractive_signing.NewPreGenParticipant(identities[i].(types.AuthKey), sid, protocol, hashset.NewHashableHashSet(identities...), cn, myTranscripts[i], prng)
		require.NoError(t, err)
	}

	return parties
}

func DoPreGenRound1(t require.TestingT, participants []*noninteractive_signing.PreGenParticipant) (round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *noninteractive_signing.Round1Broadcast]) {
	var err error
	round1BroadcastOutputs := make([]*noninteractive_signing.Round1Broadcast, len(participants))
	// round1
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		require.NoError(t, err, "failed to do lindell22 round 1")
	}

	return testutils.MapBroadcastO2I(t, participants, round1BroadcastOutputs)
}

func DoPreGenRound2(t require.TestingT, participants []*noninteractive_signing.PreGenParticipant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *noninteractive_signing.Round1Broadcast]) (round3BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *noninteractive_signing.Round2Broadcast]) {
	var err error
	round2BroadcastOutputs := make([]*noninteractive_signing.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], err = participant.Round2(round2BroadcastInputs[i])
		require.NoError(t, err, "failed to do lindell22 round 2")
	}

	return testutils.MapBroadcastO2I(t, participants, round2BroadcastOutputs)
}

func DoPreGenRound3(t require.TestingT, participants []*noninteractive_signing.PreGenParticipant, round3BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *noninteractive_signing.Round2Broadcast]) (output []*lindell22.PreProcessingMaterial) {
	var err error
	ppms := make([]*lindell22.PreProcessingMaterial, len(participants))
	for i, participant := range participants {
		ppms[i], err = participant.Round3(round3BroadcastInputs[i])
		require.NoError(t, err, "failed to do lindell22 round 3")
	}

	return ppms
}

func DoLindell2022PreGen(t require.TestingT, participants []*noninteractive_signing.PreGenParticipant) (output []*lindell22.PreProcessingMaterial) {
	r1b := DoPreGenRound1(t, participants)
	r2b := DoPreGenRound2(t, participants, r1b)
	return DoPreGenRound3(t, participants, r2b)
}
