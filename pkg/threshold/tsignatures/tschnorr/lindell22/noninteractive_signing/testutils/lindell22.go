package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/noninteractive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

func MakePreGenParticipants(tau int, identities []integration.IdentityKey, sid []byte, cohort *integration.CohortConfig, myTranscripts []transcripts.Transcript) (participants []*noninteractive_signing.PreGenParticipant, err error) {
	prng := crand.Reader
	parties := make([]*noninteractive_signing.PreGenParticipant, len(identities))
	for i := range identities {
		parties[i], err = noninteractive_signing.NewPreGenParticipant(tau, identities[i].(integration.AuthKey), sid, cohort, myTranscripts[i], prng)
		if err != nil {
			return nil, err
		}
	}

	return parties, nil
}

func DoPreGenRound1(participants []*noninteractive_signing.PreGenParticipant) (output []map[types.IdentityHash]*noninteractive_signing.Round1Broadcast, err error) {
	result := make([]map[types.IdentityHash]*noninteractive_signing.Round1Broadcast, len(participants))
	for i := range participants {
		result[i] = make(map[types.IdentityHash]*noninteractive_signing.Round1Broadcast)
	}

	for i, party := range participants {
		out, err := participants[i].Round1()
		if err != nil {
			return nil, err
		}
		for j := range participants {
			result[j][party.GetAuthKey().Hash()] = out
		}
	}

	return result, nil
}

func DoPreGenRound2(participants []*noninteractive_signing.PreGenParticipant, input []map[types.IdentityHash]*noninteractive_signing.Round1Broadcast) (outputBroadcast []map[types.IdentityHash]*noninteractive_signing.Round2Broadcast, outputUnicast []map[types.IdentityHash]*noninteractive_signing.Round2P2P, err error) {
	round2BroadcastOutputs := make([]*noninteractive_signing.Round2Broadcast, len(participants))
	round2UnicastOutputs := make([]map[types.IdentityHash]*noninteractive_signing.Round2P2P, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participant.Round2(input[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
		}
	}

	outputBroadcast = make([]map[types.IdentityHash]*noninteractive_signing.Round2Broadcast, len(participants))
	outputUnicast = make([]map[types.IdentityHash]*noninteractive_signing.Round2P2P, len(participants))
	for i := range participants {
		outputBroadcast[i] = make(map[types.IdentityHash]*noninteractive_signing.Round2Broadcast)
		outputUnicast[i] = make(map[types.IdentityHash]*noninteractive_signing.Round2P2P)
		for j := range participants {
			outputBroadcast[i][participants[j].GetAuthKey().Hash()] = round2BroadcastOutputs[j]
			outputUnicast[i][participants[j].GetAuthKey().Hash()] = round2UnicastOutputs[j][participants[i].GetAuthKey().Hash()]
		}
	}

	return outputBroadcast, outputUnicast, nil
}

func DoPreGenRound3(participants []*noninteractive_signing.PreGenParticipant, inputBroadcast []map[types.IdentityHash]*noninteractive_signing.Round2Broadcast, inputUnicast []map[types.IdentityHash]*noninteractive_signing.Round2P2P) (output []*lindell22.PreSignatureBatch, err error) {
	result := make([]*lindell22.PreSignatureBatch, len(participants))

	for i := range participants {
		out, err := participants[i].Round3(inputBroadcast[i], inputUnicast[i])
		if err != nil {
			return nil, err
		}
		result[i] = out
	}

	return result, nil
}

func DoLindell2022PreGen(participants []*noninteractive_signing.PreGenParticipant) (output []*lindell22.PreSignatureBatch, err error) {
	r1, err := DoPreGenRound1(participants)
	if err != nil {
		return nil, err
	}
	r2b, r2u, err := DoPreGenRound2(participants, r1)
	if err != nil {
		return nil, err
	}
	return DoPreGenRound3(participants, r2b, r2u)
}
