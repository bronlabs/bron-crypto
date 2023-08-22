package test_utils

import (
	crand "crypto/rand"
	"io"

	"github.com/pkg/errors"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/knox/dkg/tecdsa"
)

func MakeParticipants(curve curves.Curve, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*tecdsa.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*tecdsa.Participant, cohortConfig.Protocol.TotalParties)

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

		participants[i], err = tecdsa.NewParticipant(identity, cohortConfig, prng)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*tecdsa.Participant) (round1BroadcastOutputs []*tecdsa.Round1Broadcast, err error) {
	round1BroadcastOutputs = make([]*tecdsa.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}
	return round1BroadcastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*tecdsa.Participant, round1BroadcastOutputs []*tecdsa.Round1Broadcast) (round2BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round1Broadcast) {
	round2BroadcastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round1BroadcastOutputs[j]
			}
		}
	}
	return round2BroadcastInputs
}

func DoDkgRound2(participants []*tecdsa.Participant, round2BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round1Broadcast) (round2BroadcastOutputs []*tecdsa.Round2Broadcast, round2UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round2P2P, err error) {
	round2BroadcastOutputs = make([]*tecdsa.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]map[helper_types.IdentityHash]*tecdsa.Round2P2P, len(participants))
	for i := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participants[i].Round2(round2BroadcastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*tecdsa.Participant, round2BroadcastOutputs []*tecdsa.Round2Broadcast, round2UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round2P2P) (round3BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round2Broadcast, round3UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round2P2P) {
	round3BroadcastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round2Broadcast, len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round2BroadcastOutputs[j]
			}
		}
	}
	round3UnicastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round2P2P, len(participants))
	for i := range participants {
		round3UnicastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round2P2P)
		for j := range participants {
			if j != i {
				round3UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round2UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round3BroadcastInputs, round3UnicastInputs
}

func DoDkgRound3(participants []*tecdsa.Participant, round3BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round2Broadcast, round3UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round2P2P) (round3BroadcastOutputs []*tecdsa.Round3Broadcast, round3UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round3P2P, err error) {
	round3BroadcastOutputs = make([]*tecdsa.Round3Broadcast, len(participants))
	round3UnicastOutputs = make([]map[helper_types.IdentityHash]*tecdsa.Round3P2P, len(participants))
	for i := range participants {
		round3BroadcastOutputs[i], round3UnicastOutputs[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round3BroadcastOutputs, round3UnicastOutputs, nil
}

func MapDkgRound3OutputsToRound4Inputs(participants []*tecdsa.Participant, round3BroadcastOutputs []*tecdsa.Round3Broadcast, round3UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round3P2P) (round4BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round3Broadcast, round4UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round3P2P) {
	round4BroadcastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round3Broadcast, len(participants))
	for i := range participants {
		round4BroadcastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round3Broadcast)
		for j := range participants {
			if j != i {
				round4BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round3BroadcastOutputs[j]
			}
		}
	}

	round4UnicastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round3P2P, len(participants))
	for i := range participants {
		round4UnicastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round3P2P)
		for j := range participants {
			if j != i {
				round4UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round3UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round4BroadcastInputs, round4UnicastInputs
}

func DoDkgRound4(participants []*tecdsa.Participant, round4BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round3Broadcast, round4UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round3P2P) (round4BroadcastOutputs []*tecdsa.Round4Broadcast, round4UnicastOutputs []map[helper_types.IdentityHash]tecdsa.Round4P2P, err error) {
	round4BroadcastOutputs = make([]*tecdsa.Round4Broadcast, len(participants))
	round4UnicastOutputs = make([]map[helper_types.IdentityHash]tecdsa.Round4P2P, len(participants))
	for i := range participants {
		round4BroadcastOutputs[i], round4UnicastOutputs[i], err = participants[i].Round4(round4BroadcastInputs[i], round4UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round4BroadcastOutputs, round4UnicastOutputs, nil
}

func MapDkgRound4OutputsToRound5Inputs(participants []*tecdsa.Participant, round4BroadcastOutputs []*tecdsa.Round4Broadcast, round4UnicastOutputs []map[helper_types.IdentityHash]tecdsa.Round4P2P) (round5BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round4Broadcast, round5UnicastInputs []map[helper_types.IdentityHash]tecdsa.Round4P2P) {
	round5BroadcastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round4Broadcast, len(participants))
	for i := range participants {
		round5BroadcastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round4Broadcast)
		for j := range participants {
			if j != i {
				round5BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round4BroadcastOutputs[j]
			}
		}
	}

	round5UnicastInputs = make([]map[helper_types.IdentityHash]tecdsa.Round4P2P, len(participants))
	for i := range participants {
		round5UnicastInputs[i] = make(map[helper_types.IdentityHash]tecdsa.Round4P2P)
		for j := range participants {
			if j != i {
				round5UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round4UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round5BroadcastInputs, round5UnicastInputs
}

func DoDkgRound5(participants []*tecdsa.Participant, round5BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round4Broadcast, round5UnicastInputs []map[helper_types.IdentityHash]tecdsa.Round4P2P) (round5BroadcastOutputs []*tecdsa.Round5Broadcast, round5UnicastOutputs []map[helper_types.IdentityHash]tecdsa.Round5P2P, err error) {
	round5BroadcastOutputs = make([]*tecdsa.Round5Broadcast, len(participants))
	round5UnicastOutputs = make([]map[helper_types.IdentityHash]tecdsa.Round5P2P, len(participants))
	for i := range participants {
		round5BroadcastOutputs[i], round5UnicastOutputs[i], err = participants[i].Round5(round5BroadcastInputs[i], round5UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round5BroadcastOutputs, round5UnicastOutputs, nil
}

func MapDkgRound5OutputsToRound6Inputs(participants []*tecdsa.Participant, round5BroadcastOutputs []*tecdsa.Round5Broadcast, round5UnicastOutputs []map[helper_types.IdentityHash]tecdsa.Round5P2P) (round6BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round5Broadcast, round6UnicastInputs []map[helper_types.IdentityHash]tecdsa.Round5P2P) {
	round6BroadcastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round5Broadcast, len(participants))
	for i := range participants {
		round6BroadcastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round5Broadcast)
		for j := range participants {
			if j != i {
				round6BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round5BroadcastOutputs[j]
			}
		}
	}

	round6UnicastInputs = make([]map[helper_types.IdentityHash]tecdsa.Round5P2P, len(participants))
	for i := range participants {
		round6UnicastInputs[i] = make(map[helper_types.IdentityHash]tecdsa.Round5P2P)
		for j := range participants {
			if j != i {
				round6UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round5UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round6BroadcastInputs, round6UnicastInputs
}

func DoDkgRound6(participants []*tecdsa.Participant, round6BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round5Broadcast, round6UnicastInputs []map[helper_types.IdentityHash]tecdsa.Round5P2P) (round6BroadcastOutputs []*tecdsa.Round6Broadcast, round6UnicastOutputs []map[helper_types.IdentityHash]tecdsa.Round6P2P, err error) {
	round6BroadcastOutputs = make([]*tecdsa.Round6Broadcast, len(participants))
	round6UnicastOutputs = make([]map[helper_types.IdentityHash]tecdsa.Round6P2P, len(participants))
	for i := range participants {
		round6BroadcastOutputs[i], round6UnicastOutputs[i], err = participants[i].Round6(round6BroadcastInputs[i], round6UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round6BroadcastOutputs, round6UnicastOutputs, nil
}

func MapDkgRound6OutputsToRound7Inputs(participants []*tecdsa.Participant, round6BroadcastOutputs []*tecdsa.Round6Broadcast, round6UnicastOutputs []map[helper_types.IdentityHash]tecdsa.Round6P2P) (round7BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round6Broadcast, round7UnicastInputs []map[helper_types.IdentityHash]tecdsa.Round6P2P) {
	round7BroadcastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round6Broadcast, len(participants))
	for i := range participants {
		round7BroadcastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round6Broadcast)
		for j := range participants {
			if j != i {
				round7BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round6BroadcastOutputs[j]
			}
		}
	}

	round7UnicastInputs = make([]map[helper_types.IdentityHash]tecdsa.Round6P2P, len(participants))
	for i := range participants {
		round7UnicastInputs[i] = make(map[helper_types.IdentityHash]tecdsa.Round6P2P)
		for j := range participants {
			if j != i {
				round7UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round6UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round7BroadcastInputs, round7UnicastInputs
}

func DoDkgRound7(participants []*tecdsa.Participant, round7BroadcastInputs []map[helper_types.IdentityHash]*tecdsa.Round6Broadcast, round7UnicastInputs []map[helper_types.IdentityHash]tecdsa.Round6P2P) (round7UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round7P2P, err error) {
	round7UnicastOutputs = make([]map[helper_types.IdentityHash]*tecdsa.Round7P2P, len(participants))
	for i := range participants {
		round7UnicastOutputs[i], err = participants[i].Round7(round7BroadcastInputs[i], round7UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round7UnicastOutputs, nil
}

func MapDkgRound7OutputsToRound8Inputs(participants []*tecdsa.Participant, round7UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round7P2P) (round8UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round7P2P) {
	round8UnicastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round7P2P, len(participants))
	for i := range participants {
		round8UnicastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round7P2P)
		for j := range participants {
			if j != i {
				round8UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round7UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}
	return round8UnicastInputs
}

func DoDkgRound8(participants []*tecdsa.Participant, round8UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round7P2P) (round8UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round8P2P, err error) {
	round8UnicastOutputs = make([]map[helper_types.IdentityHash]*tecdsa.Round8P2P, len(participants))
	for i := range participants {
		round8UnicastOutputs[i], err = participants[i].Round8(round8UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round8UnicastOutputs, nil
}

func MapDkgRound8OutputsToRound9Inputs(participants []*tecdsa.Participant, round8UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round8P2P) (round9UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round8P2P) {
	round9UnicastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round8P2P, len(participants))
	for i := range participants {
		round9UnicastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round8P2P)
		for j := range participants {
			if j != i {
				round9UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round8UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}
	return round9UnicastInputs
}

func DoDkgRound9(participants []*tecdsa.Participant, round9UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round8P2P) (round9UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round9P2P, err error) {
	round9UnicastOutputs = make([]map[helper_types.IdentityHash]*tecdsa.Round9P2P, len(participants))
	for i := range participants {
		round9UnicastOutputs[i], err = participants[i].Round9(round9UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round9UnicastOutputs, nil
}

func MapDkgRound9OutputsToRound10Inputs(participants []*tecdsa.Participant, round9UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round9P2P) (round10UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round9P2P) {
	round10UnicastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round9P2P, len(participants))
	for i := range participants {
		round10UnicastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round9P2P)
		for j := range participants {
			if j != i {
				round10UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round9UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}
	return round10UnicastInputs
}

func DoDkgRound10(participants []*tecdsa.Participant, round10UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round9P2P) (round10UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round10P2P, err error) {
	round10UnicastOutputs = make([]map[helper_types.IdentityHash]*tecdsa.Round10P2P, len(participants))
	for i := range participants {
		round10UnicastOutputs[i], err = participants[i].Round10(round10UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round10UnicastOutputs, nil
}

func MapDkgRound10OutputsToRound11Inputs(participants []*tecdsa.Participant, round10UnicastOutputs []map[helper_types.IdentityHash]*tecdsa.Round10P2P) (round11UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round10P2P) {
	round11UnicastInputs = make([]map[helper_types.IdentityHash]*tecdsa.Round10P2P, len(participants))
	for i := range participants {
		round11UnicastInputs[i] = make(map[helper_types.IdentityHash]*tecdsa.Round10P2P)
		for j := range participants {
			if j != i {
				round11UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round10UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}
	return round11UnicastInputs
}

func DoDkgRound11(participants []*tecdsa.Participant, round11UnicastInputs []map[helper_types.IdentityHash]*tecdsa.Round10P2P) (shards []*tecdsa.Shard, err error) {
	shards = make([]*tecdsa.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round11(round11UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}

	return shards, nil
}
