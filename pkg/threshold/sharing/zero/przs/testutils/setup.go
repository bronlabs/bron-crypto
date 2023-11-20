package testutils

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
)

func MakeSetupParticipants(curve curves.Curve, identities []integration.IdentityKey, prng io.Reader) (participants []*setup.Participant, err error) {
	participants = make([]*setup.Participant, len(identities))
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run agree on random")
	}
	for i, identity := range identities {
		participants[i], err = setup.NewParticipant(curve, uniqueSessionId, identity.(integration.AuthKey), hashset.NewHashSet(identities), nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}
	return participants, nil
}

func DoSetupRound1(participants []*setup.Participant) (round2Outputs []map[types.IdentityHash]*setup.Round1P2P, err error) {
	round2Outputs = make([]map[types.IdentityHash]*setup.Round1P2P, len(participants))
	for i, participant := range participants {
		round2Outputs[i] = make(map[types.IdentityHash]*setup.Round1P2P)
		round2Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run Setup round 1")
		}
	}
	return round2Outputs, nil
}

func DoSetupRound2(participants []*setup.Participant, round3Inputs []map[types.IdentityHash]*setup.Round1P2P) (round3Outputs []map[types.IdentityHash]*setup.Round2P2P, err error) {
	round3Outputs = make([]map[types.IdentityHash]*setup.Round2P2P, len(participants))
	for i, participant := range participants {
		round3Outputs[i], err = participant.Round2(round3Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run Setup round 2")
		}
	}
	return round3Outputs, nil
}

func DoSetupRound3(participants []*setup.Participant, round4Inputs []map[types.IdentityHash]*setup.Round2P2P) (allPairwiseSeeds []przs.PairwiseSeeds, err error) {
	allPairwiseSeeds = make([]przs.PairwiseSeeds, len(participants))
	for i, participant := range participants {
		allPairwiseSeeds[i], err = participant.Round3(round4Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run Setup round 3")
		}
	}
	return allPairwiseSeeds, nil
}
