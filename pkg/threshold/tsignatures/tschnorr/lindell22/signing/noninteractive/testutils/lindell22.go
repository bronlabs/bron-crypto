package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	noninteractive_signing "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/noninteractive"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var cn = randomisedFischlin.Name

func MakePreGenParticipants(identities []types.IdentityKey, sid []byte, protocol types.ThresholdProtocol, myTranscripts []transcripts.Transcript) (participants []*noninteractive_signing.PreGenParticipant, err error) {
	prng := crand.Reader
	parties := make([]*noninteractive_signing.PreGenParticipant, len(identities))
	for i := range identities {
		parties[i], err = noninteractive_signing.NewPreGenParticipant(identities[i].(types.AuthKey), sid, protocol, hashset.NewHashableHashSet(identities...), cn, myTranscripts[i], prng)
		if err != nil {
			return nil, err
		}
	}

	return parties, nil
}

func DoPreGenRound1(participants []*noninteractive_signing.PreGenParticipant) (round2BroadcastInputs []types.RoundMessages[*noninteractive_signing.Round1Broadcast], err error) {
	round1BroadcastOutputs := make([]*noninteractive_signing.Round1Broadcast, len(participants))
	// round1
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 1")
		}
	}

	return testutils.MapBroadcastO2I(participants, round1BroadcastOutputs), nil
}

func DoPreGenRound2(participants []*noninteractive_signing.PreGenParticipant, round2BroadcastInputs []types.RoundMessages[*noninteractive_signing.Round1Broadcast]) (round3BroadcastInputs []types.RoundMessages[*noninteractive_signing.Round2Broadcast], err error) {
	round2BroadcastOutputs := make([]*noninteractive_signing.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], err = participant.Round2(round2BroadcastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
		}
	}

	return testutils.MapBroadcastO2I(participants, round2BroadcastOutputs), nil
}

func DoPreGenRound3(participants []*noninteractive_signing.PreGenParticipant, round3BroadcastInputs []types.RoundMessages[*noninteractive_signing.Round2Broadcast]) (output []*lindell22.PreProcessingMaterial, err error) {
	ppms := make([]*lindell22.PreProcessingMaterial, len(participants))
	for i, participant := range participants {
		ppms[i], err = participant.Round3(round3BroadcastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 3")
		}
	}

	return ppms, nil
}

func DoLindell2022PreGen(participants []*noninteractive_signing.PreGenParticipant) (output []*lindell22.PreProcessingMaterial, err error) {
	r1b, err := DoPreGenRound1(participants)
	if err != nil {
		return nil, err
	}
	r2b, err := DoPreGenRound2(participants, r1b)
	if err != nil {
		return nil, err
	}
	return DoPreGenRound3(participants, r2b)
}
