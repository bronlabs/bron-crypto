package test_utils

import (
	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/przs"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/przs/sample"
)

func MakeSampleParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, seeds []przs.PairwiseSeeds) (participants []*sample.Participant, err error) {
	participants = make([]*sample.Participant, len(identities))

	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(cohortConfig.CipherSuite.Curve, identities)
	if err != nil {
		return nil, err
	}
	for i, identity := range identities {
		participants[i], err = sample.NewParticipant(cohortConfig, uniqueSessionId, identity, seeds[i], hashset.NewHashSet(identities))
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoSample(participants []*sample.Participant) (samples []przs.Sample, err error) {
	samples = make([]przs.Sample, len(participants))
	for i, participant := range participants {
		samples[i], err = participant.Sample()
		if err != nil {
			return nil, err
		}
	}
	return samples, nil
}
