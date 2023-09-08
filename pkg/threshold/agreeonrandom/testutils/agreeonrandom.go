package testutils

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/threshold/agreeonrandom"
)

func ProduceSharedRandomValue(curve curves.Curve, identities []integration.IdentityKey, prng io.Reader) ([]byte, error) {
	var participants []*agreeonrandom.Participant
	set := hashset.NewHashSet(identities)
	for _, identity := range set.Iter() {
		participant, err := agreeonrandom.NewParticipant(curve, identity, set, nil, prng)
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
	r2Out, err := DoRound2(participants, r2In)
	if err != nil {
		return nil, err
	}
	r3In := MapRound2OutputsToRound3Inputs(participants, r2Out)
	agreeOnRandoms, err := DoRound3(participants, r3In)

	if err != nil {
		return nil, err
	}
	if len(agreeOnRandoms) != set.Len() {
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

func MapRound1OutputsToRound2Inputs(participants []*agreeonrandom.Participant, round1Outputs []*agreeonrandom.Round1Broadcast) (round2Inputs []map[types.IdentityHash]*agreeonrandom.Round1Broadcast) {
	round2Inputs = make([]map[types.IdentityHash]*agreeonrandom.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[types.IdentityHash]*agreeonrandom.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey.Hash()] = round1Outputs[j]
			}
		}
	}
	return round2Inputs
}

func DoRound2(participants []*agreeonrandom.Participant, round2Inputs []map[types.IdentityHash]*agreeonrandom.Round1Broadcast) (round2Outputs []*agreeonrandom.Round2Broadcast, err error) {
	round2Outputs = make([]*agreeonrandom.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2Outputs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapRound2OutputsToRound3Inputs(participants []*agreeonrandom.Participant, round1Outputs []*agreeonrandom.Round2Broadcast) (round3Inputs []map[types.IdentityHash]*agreeonrandom.Round2Broadcast) {
	round3Inputs = make([]map[types.IdentityHash]*agreeonrandom.Round2Broadcast, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[types.IdentityHash]*agreeonrandom.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].MyIdentityKey.Hash()] = round1Outputs[j]
			}
		}
	}
	return round3Inputs
}

func DoRound3(participants []*agreeonrandom.Participant, round2Inputs []map[types.IdentityHash]*agreeonrandom.Round2Broadcast) (results [][]byte, err error) {
	results = make([][]byte, len(participants))
	for i, participant := range participants {
		results[i], err = participant.Round3(round2Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}
