package test_utils

import (
	crand "crypto/rand"
	"fmt"

	"github.com/copperexchange/knox-primitives/pkg/agreeonrandom"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
)

func ProduceSharedRandomValue(curve curves.Curve, identities []integration.IdentityKey) ([]byte, error) {
	var participants []*agreeonrandom.Participant
	for _, identity := range identities {
		participant, err := agreeonrandom.NewParticipant(curve, identity, hashset.NewHashSet(identities), nil, crand.Reader)
		if err != nil {
			return nil, err
		}
		participants = append(participants, participant)
	}

	r1Out, err := DoRound1(participants)
	if err != nil {
		return nil, err
	}
	r2In := MapRound1OutputsToRound2Inputs(participants, r1Out)
	agreeOnRandoms, err := DoRound2(participants, r2In)
	if err != nil {
		return nil, err
	}
	if len(agreeOnRandoms) != len(identities) {
		return nil, fmt.Errorf("expected %d agreeOnRandoms, got %d", len(identities), len(agreeOnRandoms))
	}

	// check all values in agreeOnRandoms the same
	for j := 1; j < len(agreeOnRandoms); j++ {
		if len(agreeOnRandoms[0]) != len(agreeOnRandoms[j]) {
			return nil, fmt.Errorf("slices are not equal")
		}

		for i := range agreeOnRandoms[0] {
			if agreeOnRandoms[0][i] != agreeOnRandoms[j][i] {
				return nil, fmt.Errorf("slices are not equal")
			}
		}
	}

	return agreeOnRandoms[0], nil
}

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

func MapRound1OutputsToRound2Inputs(participants []*agreeonrandom.Participant, round1Outputs []*agreeonrandom.Round1Broadcast) (round2Inputs []map[helper_types.IdentityHash]*agreeonrandom.Round1Broadcast) {
	round2Inputs = make([]map[helper_types.IdentityHash]*agreeonrandom.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[helper_types.IdentityHash]*agreeonrandom.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey.Hash()] = round1Outputs[j]
			}
		}
	}
	return round2Inputs
}

func DoRound2(participants []*agreeonrandom.Participant, round2Inputs []map[helper_types.IdentityHash]*agreeonrandom.Round1Broadcast) (results [][]byte, err error) {
	results = make([][]byte, len(participants))
	for i, participant := range participants {
		results[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}
