package test_utils

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	lindell17_dkg "github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/keygen/dkg"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript"
	"github.com/pkg/errors"
	"io"
)

func MakeParticipants(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares, transcripts []transcript.Transcript, prngs []io.Reader) (participants []*lindell17_dkg.Participant, err error) {
	if len(identities) != cohortConfig.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.TotalParties)
	}

	participants = make([]*lindell17_dkg.Participant, cohortConfig.TotalParties)
	for i, identity := range identities {
		var prng io.Reader
		if prngs != nil && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}
		var transcript transcript.Transcript
		if transcripts != nil && transcripts[i] != nil {
			transcript = transcripts[i]
		}

		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("given test identity not in cohort (problem in tests?)")
		}
		participants[i], err = lindell17_dkg.NewBackupParticipant(identity, signingShares[i], publicKeyShares[i], cohortConfig, prng, sid, transcript)
	}

	return participants, nil
}

func DoDkgRound1(participants []*lindell17_dkg.Participant) (round1BroadcastOutputs []*lindell17_dkg.Round1Broadcast, err error) {
	round1BroadcastOutputs = make([]*lindell17_dkg.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1BroadcastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*lindell17_dkg.Participant, round1BroadcastOutputs []*lindell17_dkg.Round1Broadcast) (round2BroadcastInputs []map[integration.IdentityKey]*lindell17_dkg.Round1Broadcast) {
	round2BroadcastInputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey()] = round1BroadcastOutputs[j]
			}
		}
	}

	return round2BroadcastInputs
}

func DoDkgRound2(participants []*lindell17_dkg.Participant, round2BroadcastInputs []map[integration.IdentityKey]*lindell17_dkg.Round1Broadcast) (round2Outputs []*lindell17_dkg.Round2Broadcast, err error) {
	round2Outputs = make([]*lindell17_dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*lindell17_dkg.Participant, round2Outputs []*lindell17_dkg.Round2Broadcast) (round3Inputs []map[integration.IdentityKey]*lindell17_dkg.Round2Broadcast) {
	round3Inputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].GetIdentityKey()] = round2Outputs[j]
			}
		}
	}

	return round3Inputs
}

func DoDkgRound3(participants []*lindell17_dkg.Participant, round3Inputs []map[integration.IdentityKey]*lindell17_dkg.Round2Broadcast) (round3Outputs []*lindell17_dkg.Round3Broadcast, err error) {
	round3Outputs = make([]*lindell17_dkg.Round3Broadcast, len(participants))
	for i := range participants {
		round3Outputs[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round3Outputs, nil
}

func MapDkgRound3OutputsToRound4Inputs(participants []*lindell17_dkg.Participant, round3Outputs []*lindell17_dkg.Round3Broadcast) (round4Inputs []map[integration.IdentityKey]*lindell17_dkg.Round3Broadcast) {
	round4Inputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round3Broadcast, len(participants))
	for i := range participants {
		round4Inputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round3Broadcast)
		for j := range participants {
			if j != i {
				round4Inputs[i][participants[j].GetIdentityKey()] = round3Outputs[j]
			}
		}
	}

	return round4Inputs
}

func DoDkgRound4(participants []*lindell17_dkg.Participant, round4Inputs []map[integration.IdentityKey]*lindell17_dkg.Round3Broadcast) (round4Unicast []map[integration.IdentityKey]*lindell17_dkg.Round4P2P, err error) {
	round4Outputs := make([]map[integration.IdentityKey]*lindell17_dkg.Round4P2P, len(participants))
	for i := range participants {
		round4Outputs[i], err = participants[i].Round4(round4Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round4Outputs, nil
}

func MapDkgRound4OutputsToRound5Inputs(participants []*lindell17_dkg.Participant, round4UnicastOutputs []map[integration.IdentityKey]*lindell17_dkg.Round4P2P) (round5UnicastInputs []map[integration.IdentityKey]*lindell17_dkg.Round4P2P) {
	round5UnicastInputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round4P2P, len(participants))
	for i := range participants {
		round5UnicastInputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round4P2P)
		for j := range participants {
			if j != i {
				round5UnicastInputs[i][participants[j].GetIdentityKey()] = round4UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round5UnicastInputs
}

func DoDkgRound5(participants []*lindell17_dkg.Participant, round5Inputs []map[integration.IdentityKey]*lindell17_dkg.Round4P2P) (round5Outputs []map[integration.IdentityKey]*lindell17_dkg.Round5P2P, err error) {
	round5Outputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round5P2P, len(participants))
	for i := range participants {
		round5Outputs[i], err = participants[i].Round5(round5Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round5Outputs, nil
}

func MapDkgRound5OutputsToRound6Inputs(participants []*lindell17_dkg.Participant, round5UnicastOutputs []map[integration.IdentityKey]*lindell17_dkg.Round5P2P) (round6UnicastInputs []map[integration.IdentityKey]*lindell17_dkg.Round5P2P) {
	round6UnicastInputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round5P2P, len(participants))
	for i := range participants {
		round6UnicastInputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round5P2P)
		for j := range participants {
			if j != i {
				round6UnicastInputs[i][participants[j].GetIdentityKey()] = round5UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round6UnicastInputs
}

func DoDkgRound6(participants []*lindell17_dkg.Participant, round6Inputs []map[integration.IdentityKey]*lindell17_dkg.Round5P2P) (round6Outputs []map[integration.IdentityKey]*lindell17_dkg.Round6P2P, err error) {
	round6Outputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round6P2P, len(participants))
	for i := range participants {
		round6Outputs[i], err = participants[i].Round6(round6Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round6Outputs, nil
}

func MapDkgRound6OutputsToRound7Inputs(participants []*lindell17_dkg.Participant, round6UnicastOutputs []map[integration.IdentityKey]*lindell17_dkg.Round6P2P) (round7UnicastInputs []map[integration.IdentityKey]*lindell17_dkg.Round6P2P) {
	round7UnicastInputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round6P2P, len(participants))
	for i := range participants {
		round7UnicastInputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round6P2P)
		for j := range participants {
			if j != i {
				round7UnicastInputs[i][participants[j].GetIdentityKey()] = round6UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round7UnicastInputs
}

func DoDkgRound7(participants []*lindell17_dkg.Participant, round7Inputs []map[integration.IdentityKey]*lindell17_dkg.Round6P2P) (round7Outputs []map[integration.IdentityKey]*lindell17_dkg.Round7P2P, err error) {
	round7Outputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round7P2P, len(participants))
	for i := range participants {
		round7Outputs[i], err = participants[i].Round7(round7Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round7Outputs, nil
}

func MapDkgRound7OutputsToRound8Inputs(participants []*lindell17_dkg.Participant, round7UnicastOutputs []map[integration.IdentityKey]*lindell17_dkg.Round7P2P) (round8UnicastInputs []map[integration.IdentityKey]*lindell17_dkg.Round7P2P) {
	round8UnicastInputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round7P2P, len(participants))
	for i := range participants {
		round8UnicastInputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round7P2P)
		for j := range participants {
			if j != i {
				round8UnicastInputs[i][participants[j].GetIdentityKey()] = round7UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round8UnicastInputs
}

func DoDkgRound8(participants []*lindell17_dkg.Participant, round8Inputs []map[integration.IdentityKey]*lindell17_dkg.Round7P2P) (shards []*lindell17.Shard, err error) {
	shards = make([]*lindell17.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round8(round8Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return shards, nil
}
