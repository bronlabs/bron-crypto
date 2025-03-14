package testutils

import (
	crand "crypto/rand"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/csprng"
	agreeonrandom_testutils "github.com/bronlabs/bron-crypto/pkg/threshold/agreeonrandom/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/sample"
)

func MakeSampleParticipants(t require.TestingT, protocol types.Protocol, identities []types.IdentityKey, seeds []rprzs.PairWiseSeeds, seededPrng csprng.CSPRNG, wrongFirstUniqueSessionId []byte) (participants []*sample.Participant, err error) {
	participants = make([]*sample.Participant, len(identities))

	random := crand.Reader
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, protocol.Curve(), identities, random)
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

func DoSample(participants []*sample.Participant) (samples []rprzs.Sample, err error) {
	sampleMap := make(map[uint]rprzs.Sample)
	for _, participant := range participants {
		index, exists := participant.IdentitySpace.Reverse().Get(participant.IdentityKey())
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
