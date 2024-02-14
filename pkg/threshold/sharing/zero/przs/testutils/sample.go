package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
)

func MakeSampleParticipants(protocol types.MPCProtocol, identities []types.IdentityKey, seeds []przs.PairWiseSeeds, seededPrng csprng.CSPRNG, wrongFirstUniqueSessionId []byte) (participants []*sample.Participant, err error) {
	participants = make([]*sample.Participant, len(identities))

	random := crand.Reader
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(protocol.Curve(), identities, random)
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
		participants[i], err = sample.NewParticipant(sid, identity.(types.AuthKey), seeds[i], protocol, hashset.NewHashableHashSet(identities...), seededPrng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not make participant")
		}
	}
	return participants, nil
}

func DoSample(participants []*sample.Participant) (samples []przs.Sample, err error) {
	sampleMap := make(map[uint]przs.Sample)
	for _, participant := range participants {
		index, exists := participant.IdentitySpace.LookUpRight(participant.IdentityKey())
		if !exists {
			return nil, errs.NewMissing("participant %x", participant.IdentityKey().PublicKey())
		}
		sampleMap[index], err = participant.Sample()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not sample")
		}
	}
	for _, s := range sampleMap {
		samples = append(samples, s)
	}
	return samples, nil
}
