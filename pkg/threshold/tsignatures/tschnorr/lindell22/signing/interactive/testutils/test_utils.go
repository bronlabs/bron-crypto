package testutils

import (
	crand "crypto/rand"
	"github.com/stretchr/testify/require"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	randomisedFischlin "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	interactive_signing "github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/interactive"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
)

var nizkCompilerName = randomisedFischlin.Name

func MakeParticipants[V schnorr.Variant[V, M], M any](t require.TestingT, sid []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards ds.Map[types.IdentityKey, *lindell22.Shard], allTranscripts []transcripts.Transcript, variant schnorr.Variant[V, M]) (participants []*interactive_signing.Cosigner[V, M]) {
	require.Len(t, identities, int(protocol.Threshold()), "invalid number of identities %d != %d", len(identities), protocol.Threshold())

	var err error
	prng := crand.Reader
	participants = make([]*interactive_signing.Cosigner[V, M], protocol.Threshold())
	for i, identity := range identities {
		require.True(t, protocol.Participants().Contains(identity), "protocol config is missing identity")
		thisShard, exists := shards.Get(identity)
		require.True(t, exists, "shard for identity %x", identity)
		participants[i], err = interactive_signing.NewCosigner[V, M](identity.(types.AuthKey), sid, hashset.NewHashableHashSet(identities...), thisShard, protocol, nizkCompilerName, allTranscripts[i], variant, prng)
		require.NoError(t, err, "failed to create cosigner")
	}

	return participants
}

func DoRound1[V schnorr.Variant[V, M], M any](t require.TestingT, participants []*interactive_signing.Cosigner[V, M]) (round2BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *interactive_signing.Round1Broadcast]) {
	var err error
	round1BroadcastOutputs := make([]*interactive_signing.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		require.NoError(t, err, "failed to do lindell22 round 1")
	}

	return testutils.MapBroadcastO2I(t, participants, round1BroadcastOutputs)
}

func DoRound2[V schnorr.Variant[V, M], M any](t require.TestingT, participants []*interactive_signing.Cosigner[V, M], round2BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *interactive_signing.Round1Broadcast]) (round3BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *interactive_signing.Round2Broadcast]) {
	var err error
	round2BroadcastOutputs := make([]*interactive_signing.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], err = participant.Round2(round2BroadcastInputs[i])
		require.NoError(t, err, "failed to do lindell22 round 2")
	}

	return testutils.MapBroadcastO2I(t, participants, round2BroadcastOutputs)
}

func DoRound3[V schnorr.Variant[V, M], M any](t require.TestingT, participants []*interactive_signing.Cosigner[V, M], round3BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *interactive_signing.Round2Broadcast], message M) (partialSignatures []*tschnorr.PartialSignature) {
	var err error
	partialSignatures = make([]*tschnorr.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round3(round3BroadcastInputs[i], message)
		require.NoError(t, err, "failed to do lindell22 round 3")
	}

	return partialSignatures
}

func RunInteractiveSigning[V schnorr.Variant[V, M], M any](t require.TestingT, participants []*interactive_signing.Cosigner[V, M], message M) (partialSignatures []*tschnorr.PartialSignature) {
	r2bi := DoRound1(t, participants)
	r3bi := DoRound2(t, participants, r2bi)
	partialSignatures = DoRound3(t, participants, r3bi, message)
	return partialSignatures
}
