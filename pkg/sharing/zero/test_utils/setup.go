package test_utils

import (
	crand "crypto/rand"
	"testing"

	agreeonrandom_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/setup"
)

func MakeSetupParticipants(t *testing.T, curve *curves.Curve, identities []integration.IdentityKey) (participants []*setup.Participant, err error) {
	participants = make([]*setup.Participant, len(identities))
	sessionId := agreeonrandom_test_utils.DoRounds(t, curve, identities, 2)
	for i, identity := range identities {
		participants[i], err = setup.NewParticipant(curve, sessionId, identity, identities, nil, crand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoSetupRound1(participants []*setup.Participant) (round2Outputs []map[integration.IdentityKey]*setup.Round1P2P, err error) {
	round2Outputs = make([]map[integration.IdentityKey]*setup.Round1P2P, len(participants))
	for i, participant := range participants {
		round2Outputs[i] = make(map[integration.IdentityKey]*setup.Round1P2P)
		round2Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapSetupRound1OutputsToRound2Inputs(participants []*setup.Participant, round2Outputs []map[integration.IdentityKey]*setup.Round1P2P) (round3Inputs []map[integration.IdentityKey]*setup.Round1P2P) {
	round3Inputs = make([]map[integration.IdentityKey]*setup.Round1P2P, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[integration.IdentityKey]*setup.Round1P2P)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].MyIdentityKey] = round2Outputs[j][participants[i].MyIdentityKey]
			}
		}
	}
	return round3Inputs
}

func DoSetupRound2(participants []*setup.Participant, round3Inputs []map[integration.IdentityKey]*setup.Round1P2P) (round3Outputs []map[integration.IdentityKey]*setup.Round2P2P, err error) {
	round3Outputs = make([]map[integration.IdentityKey]*setup.Round2P2P, len(participants))
	for i, participant := range participants {
		round3Outputs[i], err = participant.Round2(round3Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round3Outputs, nil
}

func MapSetupRound2OutputsToRound3Inputs(participants []*setup.Participant, round3Outputs []map[integration.IdentityKey]*setup.Round2P2P) (round4Inputs []map[integration.IdentityKey]*setup.Round2P2P) {
	round4Inputs = make([]map[integration.IdentityKey]*setup.Round2P2P, len(participants))
	for i := range participants {
		round4Inputs[i] = make(map[integration.IdentityKey]*setup.Round2P2P)
		for j := range participants {
			if j != i {
				round4Inputs[i][participants[j].MyIdentityKey] = round3Outputs[j][participants[i].MyIdentityKey]
			}
		}
	}
	return round4Inputs
}

func DoSetupRound3(participants []*setup.Participant, round4Inputs []map[integration.IdentityKey]*setup.Round2P2P) (allPairwiseSeeds []zero.PairwiseSeeds, err error) {
	allPairwiseSeeds = make([]zero.PairwiseSeeds, len(participants))
	for i, participant := range participants {
		allPairwiseSeeds[i], err = participant.Round3(round4Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return allPairwiseSeeds, nil
}
