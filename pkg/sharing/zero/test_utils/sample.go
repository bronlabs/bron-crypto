package test_utils

import (
	crand "crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/sample"
)

func MakeSampleParticipants(curve *curves.Curve, identities []integration.IdentityKey, seeds []zero.PairwiseSeeds) (participants []*sample.Participant, err error) {
	participants = make([]*sample.Participant, len(identities))
	for i, identity := range identities {
		participants[i], err = sample.NewParticipant(curve, identity, seeds[i], identities, nil, crand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoSampleRound1(participants []*sample.Participant) (round1Outputs []*sample.Round1Broadcast, err error) {
	round1Outputs = make([]*sample.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}
	return round1Outputs, nil
}

func MapSampleRound2OutputsToRound3Inputs(participants []*sample.Participant, round1Outputs []*sample.Round1Broadcast) (round2Inputs []map[integration.IdentityKey]*sample.Round1Broadcast) {
	round2Inputs = make([]map[integration.IdentityKey]*sample.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityKey]*sample.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey] = round1Outputs[j]
			}
		}
	}
	return round2Inputs
}

func DoSampleRound2(participants []*sample.Participant, round2Inputs []map[integration.IdentityKey]*sample.Round1Broadcast) (samples []zero.Sample, err error) {
	samples = make([]zero.Sample, len(participants))
	for i, participant := range participants {
		samples[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return samples, nil
}
