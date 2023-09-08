package test_utils

import (
	crand "crypto/rand"
	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"io"

	"github.com/pkg/errors"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/keygen/dkg"
)

func DoKeygen(curve curves.Curve, identities []integration.IdentityKey, cohortConfig *integration.CohortConfig) ([]*lindell22.Shard, error) {
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities, crand.Reader)
	if err != nil {
		return nil, err
	}

	participants, err := MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	if err != nil {
		return nil, err
	}

	r1OutsB, r1OutsU, err := DoDkgRound1(participants)
	if err != nil {
		return nil, err
	}
	for _, out := range r1OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, errs.NewFailed("output size does not match")
		}
	}

	r2InsB, r2InsU := MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2Outs, err := DoDkgRound2(participants, r2InsB, r2InsU)

	r3Ins := MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
	shards, err := DoDkgRound3(participants, r3Ins)
	return shards, nil
}

func MakeParticipants(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*dkg.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*dkg.Participant, cohortConfig.Protocol.TotalParties)
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("given test identity not in cohort (problem in tests?)")
		}
		participants[i], err = dkg.NewParticipant(uniqueSessionId, identity, cohortConfig, nil, prng)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*dkg.Participant) (round1BroadcastOutputs []*dkg.Round1Broadcast, round1UnicastOutputs []map[helper_types.IdentityHash]*dkg.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*dkg.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[helper_types.IdentityHash]*dkg.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, err
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*dkg.Participant, round1BroadcastOutputs []*dkg.Round1Broadcast, round1UnicastOutputs []map[helper_types.IdentityHash]*dkg.Round1P2P) (round2BroadcastInputs []map[helper_types.IdentityHash]*dkg.Round1Broadcast, round2UnicastInputs []map[helper_types.IdentityHash]*dkg.Round1P2P) {
	round2BroadcastInputs = make([]map[helper_types.IdentityHash]*dkg.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[helper_types.IdentityHash]*dkg.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round1BroadcastOutputs[j]
			}
		}
	}

	round2UnicastInputs = make([]map[helper_types.IdentityHash]*dkg.Round1P2P, len(participants))
	for i := range participants {
		round2UnicastInputs[i] = make(map[helper_types.IdentityHash]*dkg.Round1P2P)
		for j := range participants {
			if j != i {
				round2UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round1UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round2BroadcastInputs, round2UnicastInputs
}

func DoDkgRound2(participants []*dkg.Participant, round2BroadcastInputs []map[helper_types.IdentityHash]*dkg.Round1Broadcast, round2UnicastInputs []map[helper_types.IdentityHash]*dkg.Round1P2P) (round2Outputs []*dkg.Round2Broadcast, err error) {
	round2Outputs = make([]*dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*dkg.Participant, round3Outputs []*dkg.Round2Broadcast) (round3Inputs []map[helper_types.IdentityHash]*dkg.Round2Broadcast) {
	round3Inputs = make([]map[helper_types.IdentityHash]*dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[helper_types.IdentityHash]*dkg.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].GetIdentityKey().Hash()] = round3Outputs[j]
			}
		}
	}

	return round3Inputs
}

func DoDkgRound3(participants []*dkg.Participant, round3Inputs []map[helper_types.IdentityHash]*dkg.Round2Broadcast) (shards []*lindell22.Shard, err error) {
	shards = make([]*lindell22.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, err
		}
	}

	return shards, nil
}
