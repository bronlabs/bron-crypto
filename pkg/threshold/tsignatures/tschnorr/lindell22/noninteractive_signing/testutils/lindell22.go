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

func DoPreGenRound1(participants []*noninteractive_signing.PreGenParticipant) (round2BroadcastInputs []map[types.IdentityHash]*noninteractive_signing.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*noninteractive_signing.Round1P2P, err error) {
	round1BroadcastOutputs := make([]*noninteractive_signing.Round1Broadcast, len(participants))
	round1UnicastOutputs := make([]map[types.IdentityHash]*noninteractive_signing.Round1P2P, len(participants))
	// round1
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to do lindell22 round 1")
		}
	}

	round2BroadcastInputs = make([]map[types.IdentityHash]*noninteractive_signing.Round1Broadcast, len(participants))
	round2UnicastInputs = make([]map[types.IdentityHash]*noninteractive_signing.Round1P2P, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[types.IdentityHash]*noninteractive_signing.Round1Broadcast)
		round2UnicastInputs[i] = make(map[types.IdentityHash]*noninteractive_signing.Round1P2P)
		for j := range participants {
			if i == j {
				continue
			}
			round2BroadcastInputs[i][participants[j].GetAuthKey().Hash()] = round1BroadcastOutputs[j]
			round2UnicastInputs[i][participants[j].GetAuthKey().Hash()] = round1UnicastOutputs[j][participants[i].GetAuthKey().Hash()]
		}
	}

	return round2BroadcastInputs, round2UnicastInputs, nil
}

func DoPreGenRound2(participants []*noninteractive_signing.PreGenParticipant, round2BroadcastInputs []map[types.IdentityHash]*noninteractive_signing.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*noninteractive_signing.Round1P2P) (round3BroadcastInputs []map[types.IdentityHash]*noninteractive_signing.Round2Broadcast, round3UnicastInputs []map[types.IdentityHash]*noninteractive_signing.Round2P2P, err error) {
	round2BroadcastOutputs := make([]*noninteractive_signing.Round2Broadcast, len(participants))
	round2UnicastOutputs := make([]map[types.IdentityHash]*noninteractive_signing.Round2P2P, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participant.Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
		}
	}

	round3BroadcastInputs = make([]map[types.IdentityHash]*noninteractive_signing.Round2Broadcast, len(participants))
	round3UnicastInputs = make([]map[types.IdentityHash]*noninteractive_signing.Round2P2P, len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = make(map[types.IdentityHash]*noninteractive_signing.Round2Broadcast)
		round3UnicastInputs[i] = make(map[types.IdentityHash]*noninteractive_signing.Round2P2P)
		for j := range participants {
			if i == j {
				continue
			}
			round3BroadcastInputs[i][participants[j].GetAuthKey().Hash()] = round2BroadcastOutputs[j]
			round3UnicastInputs[i][participants[j].GetAuthKey().Hash()] = round2UnicastOutputs[j][participants[i].GetAuthKey().Hash()]
		}
	}

	return round3BroadcastInputs, round3UnicastInputs, nil
}

func DoPreGenRound3(participants []*noninteractive_signing.PreGenParticipant, round3BroadcastInputs []map[types.IdentityHash]*noninteractive_signing.Round2Broadcast, round3UnicastInputs []map[types.IdentityHash]*noninteractive_signing.Round2P2P) (output []*lindell22.PreSignatureBatch, err error) {
	batches := make([]*lindell22.PreSignatureBatch, len(participants))
	for i, participant := range participants {
		batches[i], err = participant.Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 3")
		}
	}

	return batches, nil
}

func DoLindell2022PreGen(participants []*noninteractive_signing.PreGenParticipant) (output []*lindell22.PreSignatureBatch, err error) {
	r1b, r1u, err := DoPreGenRound1(participants)
	if err != nil {
		return nil, err
	}
	r2b, r2u, err := DoPreGenRound2(participants, r1b, r1u)
	if err != nil {
		return nil, err
	}
	return DoPreGenRound3(participants, r2b, r2u)
}
