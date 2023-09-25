package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/pkg/errors"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/dkg"
)

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

func DoDkgRound1(participants []*dkg.Participant) (round1BroadcastOutputs []*dkg.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*dkg.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*dkg.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[types.IdentityHash]*dkg.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, err
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*dkg.Participant, round1BroadcastOutputs []*dkg.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*dkg.Round1P2P) (round2BroadcastInputs []map[types.IdentityHash]*dkg.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*dkg.Round1P2P) {
	round2BroadcastInputs = make([]map[types.IdentityHash]*dkg.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[types.IdentityHash]*dkg.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round1BroadcastOutputs[j]
			}
		}
	}

	round2UnicastInputs = make([]map[types.IdentityHash]*dkg.Round1P2P, len(participants))
	for i := range participants {
		round2UnicastInputs[i] = make(map[types.IdentityHash]*dkg.Round1P2P)
		for j := range participants {
			if j != i {
				round2UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round1UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round2BroadcastInputs, round2UnicastInputs
}

func DoDkgRound2(participants []*dkg.Participant, round2BroadcastInputs []map[types.IdentityHash]*dkg.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*dkg.Round1P2P) (round2Outputs []*dkg.Round2Broadcast, err error) {
	round2Outputs = make([]*dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*dkg.Participant, round3Outputs []*dkg.Round2Broadcast) (round3Inputs []map[types.IdentityHash]*dkg.Round2Broadcast) {
	round3Inputs = make([]map[types.IdentityHash]*dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[types.IdentityHash]*dkg.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].GetIdentityKey().Hash()] = round3Outputs[j]
			}
		}
	}

	return round3Inputs
}

func DoDkgRound3(participants []*dkg.Participant, round3Inputs []map[types.IdentityHash]*dkg.Round2Broadcast) (shards []*lindell22.Shard, err error) {
	shards = make([]*lindell22.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, err
		}
	}

	return shards, nil
}
