package test_utils

import (
	crand "crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/setup"
)

func MakeParticipants(curve *curves.Curve, identities []integration.IdentityKey) (participants []*setup.Participant, err error) {
	participants = make([]*setup.Participant, len(identities))
	for i, identity := range identities {
		participants[i], err = setup.NewParticipant(curve, identity, identities, nil, crand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoSetupRound1(participants []*setup.Participant) (round1Outputs []*setup.Round1Broadcast, err error) {
	round1Outputs = make([]*setup.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}
	return round1Outputs, nil
}

func MapSetupRound1OutputsToRound2Inputs(participants []*setup.Participant, round1Outputs []*setup.Round1Broadcast) (round2Inputs []map[integration.IdentityKey]*setup.Round1Broadcast) {
	round2Inputs = make([]map[integration.IdentityKey]*setup.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityKey]*setup.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey] = round1Outputs[j]
			}
		}
	}
	return round2Inputs
}

func DoSetupRound2(participants []*setup.Participant, round2Inputs []map[integration.IdentityKey]*setup.Round1Broadcast) (round2Outputs []map[integration.IdentityKey]*setup.Round2P2P, err error) {
	round2Outputs = make([]map[integration.IdentityKey]*setup.Round2P2P, len(participants))
	for i, participant := range participants {
		round2Outputs[i] = make(map[integration.IdentityKey]*setup.Round2P2P)
		round2Outputs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapSetupRound2OutputsToRound3Inputs(participants []*setup.Participant, round2Outputs []map[integration.IdentityKey]*setup.Round2P2P) (round3Inputs []map[integration.IdentityKey]*setup.Round2P2P) {
	round3Inputs = make([]map[integration.IdentityKey]*setup.Round2P2P, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[integration.IdentityKey]*setup.Round2P2P)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].MyIdentityKey] = round2Outputs[j][participants[i].MyIdentityKey]
			}
		}
	}
	return round3Inputs
}

func DoSetupRound3(participants []*setup.Participant, round3Inputs []map[integration.IdentityKey]*setup.Round2P2P) (round3Outputs []map[integration.IdentityKey]*setup.Round3P2P, err error) {
	round3Outputs = make([]map[integration.IdentityKey]*setup.Round3P2P, len(participants))
	for i, participant := range participants {
		round3Outputs[i], err = participant.Round3(round3Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round3Outputs, nil
}

func MapSetupRound3OutputsToRound4Inputs(participants []*setup.Participant, round3Outputs []map[integration.IdentityKey]*setup.Round3P2P) (round4Inputs []map[integration.IdentityKey]*setup.Round3P2P) {
	round4Inputs = make([]map[integration.IdentityKey]*setup.Round3P2P, len(participants))
	for i := range participants {
		round4Inputs[i] = make(map[integration.IdentityKey]*setup.Round3P2P)
		for j := range participants {
			if j != i {
				round4Inputs[i][participants[j].MyIdentityKey] = round3Outputs[j][participants[i].MyIdentityKey]
			}
		}
	}
	return round4Inputs
}

func DoSetupRound4(participants []*setup.Participant, round4Inputs []map[integration.IdentityKey]*setup.Round3P2P) (allPairwiseSeeds []zero.PairwiseSeeds, err error) {
	allPairwiseSeeds = make([]zero.PairwiseSeeds, len(participants))
	for i, participant := range participants {
		allPairwiseSeeds[i], err = participant.Round4(round4Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return allPairwiseSeeds, nil
}
