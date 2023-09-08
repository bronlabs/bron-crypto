package test_utils

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/threshold/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/zero/przs/setup"
)

func MakeSetupParticipants(curve curves.Curve, identities []integration.IdentityKey, prng io.Reader) (participants []*setup.Participant, err error) {
	participants = make([]*setup.Participant, len(identities))
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities, prng)
	if err != nil {
		return nil, err
	}
	for i, identity := range identities {
		participants[i], err = setup.NewParticipant(curve, uniqueSessionId, identity, hashset.NewHashSet(identities), nil, prng)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoSetupRound1(participants []*setup.Participant) (round2Outputs []map[helper_types.IdentityHash]*setup.Round1P2P, err error) {
	round2Outputs = make([]map[helper_types.IdentityHash]*setup.Round1P2P, len(participants))
	for i, participant := range participants {
		round2Outputs[i] = make(map[helper_types.IdentityHash]*setup.Round1P2P)
		round2Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapSetupRound1OutputsToRound2Inputs(participants []*setup.Participant, round2Outputs []map[helper_types.IdentityHash]*setup.Round1P2P) (round3Inputs []map[helper_types.IdentityHash]*setup.Round1P2P) {
	round3Inputs = make([]map[helper_types.IdentityHash]*setup.Round1P2P, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[helper_types.IdentityHash]*setup.Round1P2P)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].MyIdentityKey.Hash()] = round2Outputs[j][participants[i].MyIdentityKey.Hash()]
			}
		}
	}
	return round3Inputs
}

func DoSetupRound2(participants []*setup.Participant, round3Inputs []map[helper_types.IdentityHash]*setup.Round1P2P) (round3Outputs []map[helper_types.IdentityHash]*setup.Round2P2P, err error) {
	round3Outputs = make([]map[helper_types.IdentityHash]*setup.Round2P2P, len(participants))
	for i, participant := range participants {
		round3Outputs[i], err = participant.Round2(round3Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round3Outputs, nil
}

func MapSetupRound2OutputsToRound3Inputs(participants []*setup.Participant, round3Outputs []map[helper_types.IdentityHash]*setup.Round2P2P) (round4Inputs []map[helper_types.IdentityHash]*setup.Round2P2P) {
	round4Inputs = make([]map[helper_types.IdentityHash]*setup.Round2P2P, len(participants))
	for i := range participants {
		round4Inputs[i] = make(map[helper_types.IdentityHash]*setup.Round2P2P)
		for j := range participants {
			if j != i {
				round4Inputs[i][participants[j].MyIdentityKey.Hash()] = round3Outputs[j][participants[i].MyIdentityKey.Hash()]
			}
		}
	}
	return round4Inputs
}

func DoSetupRound3(participants []*setup.Participant, round4Inputs []map[helper_types.IdentityHash]*setup.Round2P2P) (allPairwiseSeeds []przs.PairwiseSeeds, err error) {
	allPairwiseSeeds = make([]przs.PairwiseSeeds, len(participants))
	for i, participant := range participants {
		allPairwiseSeeds[i], err = participant.Round3(round4Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return allPairwiseSeeds, nil
}
