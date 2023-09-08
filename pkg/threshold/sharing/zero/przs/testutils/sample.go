package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	agreeonrandom_testutils "github.com/copperexchange/krypton/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton/pkg/threshold/sharing/zero/przs/sample"
)

func MakeSampleParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, seeds []przs.PairwiseSeeds) (participants []*sample.Participant, err error) {
	participants = make([]*sample.Participant, len(identities))

	random := crand.Reader
	uniqueSessionId, err := agreeonrandom_testutils.ProduceSharedRandomValue(cohortConfig.CipherSuite.Curve, identities, random)
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
	sampleMap := make(map[int]przs.Sample)
	for _, participant := range participants {
		sampleMap[participant.MySharingId], err = participant.Sample()
		if err != nil {
			return nil, err
		}
	}
	for _, s := range sampleMap {
		samples = append(samples, s)
	}
	return samples, nil
}
