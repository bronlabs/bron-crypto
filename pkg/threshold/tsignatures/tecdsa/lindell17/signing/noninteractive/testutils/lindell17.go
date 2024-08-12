package testutils

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	noninteractive_signing "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/signing/noninteractive"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var cn = randomisedFischlin.Name

func MakeTranscripts(label string, identities []types.IdentityKey) []transcripts.Transcript {
	allTranscripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		allTranscripts[i] = hagrid.NewTranscript(label, nil)
	}

	return allTranscripts
}

func MakePreGenParticipants(t require.TestingT, identities []types.IdentityKey, sid []byte, protocol types.ThresholdProtocol, allTranscripts []transcripts.Transcript) (participants []*noninteractive_signing.PreGenParticipant) {
	var err error
	prng := crand.Reader
	parties := make([]*noninteractive_signing.PreGenParticipant, len(identities))
	for i := range identities {
		parties[i], err = noninteractive_signing.NewPreGenParticipant(sid, allTranscripts[i], identities[i].(types.AuthKey), protocol, hashset.NewHashableHashSet(identities...), cn, prng)
		require.NoError(t, err)
	}

	return parties
}

func DoPreGenRound1(t require.TestingT, participants []*noninteractive_signing.PreGenParticipant) (output []network.RoundMessages[types.ThresholdProtocol, *noninteractive_signing.Round1Broadcast]) {
	var err error
	result := make([]*noninteractive_signing.Round1Broadcast, len(participants))
	for i, party := range participants {
		result[i], err = party.Round1()
		require.NoError(t, err)
	}

	r1Out := testutils.MapBroadcastO2I(t, participants, result)
	return r1Out
}

func DoPreGenRound2(t require.TestingT, participants []*noninteractive_signing.PreGenParticipant, input []network.RoundMessages[types.ThresholdProtocol, *noninteractive_signing.Round1Broadcast]) (output []network.RoundMessages[types.ThresholdProtocol, *noninteractive_signing.Round2Broadcast]) {
	var err error
	result := make([]*noninteractive_signing.Round2Broadcast, len(participants))
	for i, party := range participants {
		result[i], err = party.Round2(input[i])
		require.NoError(t, err)
	}

	return testutils.MapBroadcastO2I(t, participants, result)
}

func DoPreGenRound3(t require.TestingT, participants []*noninteractive_signing.PreGenParticipant, input []network.RoundMessages[types.ThresholdProtocol, *noninteractive_signing.Round2Broadcast]) (output []*lindell17.PreProcessingMaterial) {
	var err error
	result := make([]*lindell17.PreProcessingMaterial, len(participants))
	for i, party := range participants {
		result[i], err = party.Round3(input[i])
		require.NoError(t, err)
	}

	return result
}

func DoLindell2017PreGen(t require.TestingT, participants []*noninteractive_signing.PreGenParticipant) (output []*lindell17.PreProcessingMaterial) {
	r1 := DoPreGenRound1(t, participants)
	r2 := DoPreGenRound2(t, participants, r1)
	return DoPreGenRound3(t, participants, r2)
}
