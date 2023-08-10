package test_utils

import (
	crand "crypto/rand"

	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/setup"
)

func MakeSetupParticipants(curve *curves.Curve, identities []integration.IdentityKey) (participants []*setup.Participant, err error) {
	participants = make([]*setup.Participant, len(identities))
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	if err != nil {
		return nil, err
	}
	for i, identity := range identities {
		participants[i], err = setup.NewParticipant(curve, uniqueSessionId, identity, identities, nil, crand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoSetupRound1(participants []*setup.Participant) (round2Outputs []*hashmap.HashMap[integration.IdentityKey, *setup.Round1P2P], err error) {
	round2Outputs = make([]*hashmap.HashMap[integration.IdentityKey, *setup.Round1P2P], len(participants))
	for i, participant := range participants {
		round2Outputs[i] = hashmap.NewHashMap[integration.IdentityKey, *setup.Round1P2P]()
		round2Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapSetupRound1OutputsToRound2Inputs(participants []*setup.Participant, round2Outputs []*hashmap.HashMap[integration.IdentityKey, *setup.Round1P2P]) (round3Inputs []*hashmap.HashMap[integration.IdentityKey, *setup.Round1P2P]) {
	round3Inputs = make([]*hashmap.HashMap[integration.IdentityKey, *setup.Round1P2P], len(participants))
	for i := range participants {
		round3Inputs[i] = hashmap.NewHashMap[integration.IdentityKey, *setup.Round1P2P]()
		for j := range participants {
			if j != i {
				output, _ := round2Outputs[j].Get(participants[i].MyIdentityKey)
				round3Inputs[i].Put(participants[j].MyIdentityKey, output)
			}
		}
	}
	return round3Inputs
}

func DoSetupRound2(participants []*setup.Participant, round3Inputs []*hashmap.HashMap[integration.IdentityKey, *setup.Round1P2P]) (round3Outputs []*hashmap.HashMap[integration.IdentityKey, *setup.Round2P2P], err error) {
	round3Outputs = make([]*hashmap.HashMap[integration.IdentityKey, *setup.Round2P2P], len(participants))
	for i, participant := range participants {
		round3Outputs[i], err = participant.Round2(round3Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round3Outputs, nil
}

func MapSetupRound2OutputsToRound3Inputs(participants []*setup.Participant, round3Outputs []*hashmap.HashMap[integration.IdentityKey, *setup.Round2P2P]) (round4Inputs []*hashmap.HashMap[integration.IdentityKey, *setup.Round2P2P]) {
	round4Inputs = make([]*hashmap.HashMap[integration.IdentityKey, *setup.Round2P2P], len(participants))
	for i := range participants {
		round4Inputs[i] = hashmap.NewHashMap[integration.IdentityKey, *setup.Round2P2P]()
		for j := range participants {
			if j != i {
				output, _ := round3Outputs[j].Get(participants[i].MyIdentityKey)
				round4Inputs[i].Put(participants[j].MyIdentityKey, output)
			}
		}
	}
	return round4Inputs
}

func DoSetupRound3(participants []*setup.Participant, round4Inputs []*hashmap.HashMap[integration.IdentityKey, *setup.Round2P2P]) (allPairwiseSeeds []zero.PairwiseSeeds, err error) {
	allPairwiseSeeds = make([]zero.PairwiseSeeds, len(participants))
	for i, participant := range participants {
		allPairwiseSeeds[i], err = participant.Round3(round4Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return allPairwiseSeeds, nil
}
