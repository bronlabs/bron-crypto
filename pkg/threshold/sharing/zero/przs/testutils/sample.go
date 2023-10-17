package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
)

func MakeSampleParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, seeds []przs.PairwiseSeeds, seededPrng csprng.CSPRNG, wrongFirstUniqueSessionId []byte) (participants []*sample.Participant, err error) {
	participants = make([]*sample.Participant, len(identities))

	random := crand.Reader
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(cohortConfig.CipherSuite.Curve, identities, random)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce shared random value")
	}
	var sid []byte
	for i, identity := range identities {
		if wrongFirstUniqueSessionId != nil && i == 0 {
			sid = wrongFirstUniqueSessionId
		} else {
			sid = uniqueSessionId
		}
		participants[i], err = sample.NewParticipant(cohortConfig, sid, identity, seeds[i], hashset.NewHashSet(identities), seededPrng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not make participant")
		}
	}
	return participants, nil
}

func DoSample(participants []*sample.Participant) (samples []przs.Sample, err error) {
	sampleMap := make(map[int]przs.Sample)
	for _, participant := range participants {
		sampleMap[participant.MySharingId], err = participant.Sample()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not sample")
		}
	}
	for _, s := range sampleMap {
		samples = append(samples, s)
	}
	return samples, nil
}
