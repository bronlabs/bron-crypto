package test_utils

import (
	crand "crypto/rand"

	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/dkls23/keygen/dkg"
	"github.com/pkg/errors"
)

func MakeParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*dkg.Participant, err error) {
	if len(identities) != cohortConfig.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.TotalParties)
	}

	participants = make([]*dkg.Participant, cohortConfig.TotalParties)
	for i, identity := range identities {
		var prng io.Reader
		if prngs != nil && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("given test identity not in cohort (problem in tests?)")
		}

		participants[i], err = dkg.NewParticipant(identity, cohortConfig, prng)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*dkg.Participant) (round1Outputs []*dkg.Round1Broadcast, err error) {
	round1Outputs = make([]*dkg.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1Outputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*dkg.Participant, round1Outputs []*dkg.Round1Broadcast) (round2Inputs []map[integration.IdentityKey]*dkg.Round1Broadcast) {
	round2Inputs = make([]map[integration.IdentityKey]*dkg.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityKey]*dkg.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].GetIdentityKey()] = round1Outputs[j]
			}
		}
	}

	return round2Inputs
}

func DoDkgRound2(participants []*dkg.Participant, round2Inputs []map[integration.IdentityKey]*dkg.Round1Broadcast) (round2BroadcastOutputs []*dkg.Round2Broadcast, round2UnicastOutputs []map[integration.IdentityKey]*dkg.Round2P2P, err error) {
	round2BroadcastOutputs = make([]*dkg.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]map[integration.IdentityKey]*dkg.Round2P2P, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*dkg.Participant, round2BroadcastOutputs []*dkg.Round2Broadcast, round2UnicastOutputs []map[integration.IdentityKey]*dkg.Round2P2P) (round3BroadcastInputs []map[integration.IdentityKey]*dkg.Round2Broadcast, round3UnicastInputs []map[integration.IdentityKey]*dkg.Round2P2P) {
	round3BroadcastInputs = make([]map[integration.IdentityKey]*dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = make(map[integration.IdentityKey]*dkg.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3BroadcastInputs[i][participants[j].GetIdentityKey()] = round2BroadcastOutputs[j]
			}
		}
	}

	round3UnicastInputs = make([]map[integration.IdentityKey]*dkg.Round2P2P, len(participants))
	for i := range participants {
		round3UnicastInputs[i] = make(map[integration.IdentityKey]*dkg.Round2P2P)
		for j := range participants {
			if j != i {
				round3UnicastInputs[i][participants[j].GetIdentityKey()] = round2UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round3BroadcastInputs, round3UnicastInputs
}

func DoDkgRound3(participants []*dkg.Participant, round3BroadcastInputs []map[integration.IdentityKey]*dkg.Round2Broadcast, round3UnicastInputs []map[integration.IdentityKey]*dkg.Round2P2P) (round3Outputs []map[integration.IdentityKey]*dkg.Round3P2P, err error) {
	round3Outputs = make([]map[integration.IdentityKey]*dkg.Round3P2P, len(participants))
	for i := range participants {
		round3Outputs[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}

	return round3Outputs, nil
}

func MapDkgRound3OutputsToRound4Inputs(participants []*dkg.Participant, round3UnicastOutputs []map[integration.IdentityKey]*dkg.Round3P2P) (round4UnicastInputs []map[integration.IdentityKey]*dkg.Round3P2P) {
	round4UnicastInputs = make([]map[integration.IdentityKey]*dkg.Round3P2P, len(participants))
	for i := range participants {
		round4UnicastInputs[i] = make(map[integration.IdentityKey]*dkg.Round3P2P)
		for j := range participants {
			if j != i {
				round4UnicastInputs[i][participants[j].GetIdentityKey()] = round3UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round4UnicastInputs
}

func DoDkgRound4(participants []*dkg.Participant, round4UnicastInputs []map[integration.IdentityKey]*dkg.Round3P2P) (shards []*dkls23.Shard, err error) {
	shards = make([]*dkls23.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round4(round4UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}

	return shards, nil
}
