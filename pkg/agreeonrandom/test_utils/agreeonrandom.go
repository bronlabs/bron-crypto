package test_utils

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
)

func DoRound1(participants []*agreeonrandom.Participant) (round1Outputs []*agreeonrandom.Round1Broadcast, err error) {
	round1Outputs = make([]*agreeonrandom.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}
	return round1Outputs, nil
}

func MapRound1OutputsToRound2Inputs(participants []*agreeonrandom.Participant, round1Outputs []*agreeonrandom.Round1Broadcast) (round2Inputs []map[integration.IdentityKey]*agreeonrandom.Round1Broadcast) {
	round2Inputs = make([]map[integration.IdentityKey]*agreeonrandom.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityKey]*agreeonrandom.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey] = round1Outputs[j]
			}
		}
	}
	return round2Inputs
}

func DoRound2(participants []*agreeonrandom.Participant, round2Inputs []map[integration.IdentityKey]*agreeonrandom.Round1Broadcast) (results [][]byte, err error) {
	results = make([][]byte, len(participants))
	for i, participant := range participants {
		results[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}
