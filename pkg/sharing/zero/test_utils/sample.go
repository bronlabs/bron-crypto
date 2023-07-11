package test_utils

import (
	"testing"

	agreeonrandom_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/sample"
)

func MakeSampleParticipants(t *testing.T, curve *curves.Curve, identities []integration.IdentityKey, seeds []zero.PairwiseSeeds, invalidSidParticipant int) (participants []*sample.Participant, err error) {
	participants = make([]*sample.Participant, len(identities))

	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, len(identities))
	for i, identity := range identities {
		if i == invalidSidParticipant {
			participants[i], err = sample.NewParticipant(curve, []byte(""), identity, seeds[i], identities)
		} else {
			participants[i], err = sample.NewParticipant(curve, uniqueSessionId, identity, seeds[i], identities)
		}
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoSample(participants []*sample.Participant) (samples []zero.Sample, err error) {
	samples = make([]zero.Sample, len(participants))
	for i, participant := range participants {
		samples[i], err = participant.Sample()
		if err != nil {
			return nil, err
		}
	}
	return samples, nil
}
