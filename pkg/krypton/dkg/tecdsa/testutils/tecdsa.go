package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/krypton/dkg/tecdsa"
)

func MakeParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*tecdsa.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
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
			return nil, errs.NewMissing("given test identity not in cohort (problem in tests?)")
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

func DoDkgRound2(participants []*tecdsa.Participant, round1BroadcastOutputs []map[types.IdentityHash]*tecdsa.Round1Broadcast) (round2BroadcastOutputs []*tecdsa.Round2Broadcast, err error) {
	round2BroadcastOutputs = make([]*tecdsa.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], err = participant.Round2(round1BroadcastOutputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2BroadcastOutputs, nil
}

func MapDkgRoundArray[T any](participants []*tecdsa.Participant, round2BroadcastOutputs []*T) (round2BroadcastInputs []map[types.IdentityHash]*T) {
	round2BroadcastInputs = make([]map[types.IdentityHash]*T, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[types.IdentityHash]*T)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round2BroadcastOutputs[j]
			}
		}
	}
	return round2BroadcastInputs
}

func DoDkgRound3(participants []*tecdsa.Participant, round2BroadcastInputs []map[types.IdentityHash]*tecdsa.Round2Broadcast) (round2BroadcastOutputs []*tecdsa.Round3Broadcast, round2UnicastOutputs []map[types.IdentityHash]*tecdsa.Round3P2P, err error) {
	round2BroadcastOutputs = make([]*tecdsa.Round3Broadcast, len(participants))
	round2UnicastOutputs = make([]map[types.IdentityHash]*tecdsa.Round3P2P, len(participants))
	for i := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participants[i].Round3(round2BroadcastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func DoDkgRound4(participants []*tecdsa.Participant, round3BroadcastInputs []map[types.IdentityHash]*tecdsa.Round3Broadcast, round3UnicastInputs []map[types.IdentityHash]*tecdsa.Round3P2P) (round3BroadcastOutputs []*tecdsa.Round4Broadcast, round3UnicastOutputs []map[types.IdentityHash]*tecdsa.Round4P2P, err error) {
	round3BroadcastOutputs = make([]*tecdsa.Round4Broadcast, len(participants))
	round3UnicastOutputs = make([]map[types.IdentityHash]*tecdsa.Round4P2P, len(participants))
	for i := range participants {
		round3BroadcastOutputs[i], round3UnicastOutputs[i], err = participants[i].Round4(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round3BroadcastOutputs, round3UnicastOutputs, nil
}

func DoDkgRound5(participants []*tecdsa.Participant, round4BroadcastInputs []map[types.IdentityHash]*tecdsa.Round4Broadcast, round4UnicastInputs []map[types.IdentityHash]*tecdsa.Round4P2P) (round4BroadcastOutputs []*tecdsa.Round5Broadcast, round4UnicastOutputs []map[types.IdentityHash]tecdsa.Round5P2P, err error) {
	round4BroadcastOutputs = make([]*tecdsa.Round5Broadcast, len(participants))
	round4UnicastOutputs = make([]map[types.IdentityHash]tecdsa.Round5P2P, len(participants))
	for i := range participants {
		round4BroadcastOutputs[i], round4UnicastOutputs[i], err = participants[i].Round5(round4BroadcastInputs[i], round4UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round4BroadcastOutputs, round4UnicastOutputs, nil
}

func DoDkgRound6(participants []*tecdsa.Participant, round5BroadcastInputs []map[types.IdentityHash]*tecdsa.Round5Broadcast, round5UnicastInputs []map[types.IdentityHash]tecdsa.Round5P2P) (round5BroadcastOutputs []*tecdsa.Round6Broadcast, round5UnicastOutputs []map[types.IdentityHash]tecdsa.Round6P2P, err error) {
	round5BroadcastOutputs = make([]*tecdsa.Round6Broadcast, len(participants))
	round5UnicastOutputs = make([]map[types.IdentityHash]tecdsa.Round6P2P, len(participants))
	for i := range participants {
		round5BroadcastOutputs[i], round5UnicastOutputs[i], err = participants[i].Round6(round5BroadcastInputs[i], round5UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round5BroadcastOutputs, round5UnicastOutputs, nil
}

func DoDkgRound7(participants []*tecdsa.Participant, round6BroadcastInputs []map[types.IdentityHash]*tecdsa.Round6Broadcast, round6UnicastInputs []map[types.IdentityHash]tecdsa.Round6P2P) (round6BroadcastOutputs []*tecdsa.Round7Broadcast, round6UnicastOutputs []map[types.IdentityHash]tecdsa.Round7P2P, err error) {
	round6BroadcastOutputs = make([]*tecdsa.Round7Broadcast, len(participants))
	round6UnicastOutputs = make([]map[types.IdentityHash]tecdsa.Round7P2P, len(participants))
	for i := range participants {
		round6BroadcastOutputs[i], round6UnicastOutputs[i], err = participants[i].Round7(round6BroadcastInputs[i], round6UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round6BroadcastOutputs, round6UnicastOutputs, nil
}

func MapDkgRoundP2P[K any, P any](participants []*tecdsa.Participant, round6BroadcastOutputs []*K, round6UnicastOutputs []map[types.IdentityHash]P) (round7BroadcastInputs []map[types.IdentityHash]*K, round7UnicastInputs []map[types.IdentityHash]P) {
	round7BroadcastInputs = make([]map[types.IdentityHash]*K, len(participants))
	for i := range participants {
		round7BroadcastInputs[i] = make(map[types.IdentityHash]*K)
		for j := range participants {
			if j != i {
				round7BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round6BroadcastOutputs[j]
			}
		}
	}

	round7UnicastInputs = make([]map[types.IdentityHash]P, len(participants))
	for i := range participants {
		round7UnicastInputs[i] = make(map[types.IdentityHash]P)
		for j := range participants {
			if j != i {
				round7UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round6UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round7BroadcastInputs, round7UnicastInputs
}

func DoDkgRound8(participants []*tecdsa.Participant, round7BroadcastInputs []map[types.IdentityHash]*tecdsa.Round7Broadcast, round7UnicastInputs []map[types.IdentityHash]tecdsa.Round7P2P) (round7UnicastOutputs []map[types.IdentityHash]*tecdsa.Round8P2P, err error) {
	round7UnicastOutputs = make([]map[types.IdentityHash]*tecdsa.Round8P2P, len(participants))
	for i := range participants {
		round7UnicastOutputs[i], err = participants[i].Round8(round7BroadcastInputs[i], round7UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round7UnicastOutputs, nil
}

func DoDkgRound9(participants []*tecdsa.Participant, round8UnicastInputs []map[types.IdentityHash]*tecdsa.Round8P2P) (round8UnicastOutputs []map[types.IdentityHash]*tecdsa.Round9P2P, err error) {
	round8UnicastOutputs = make([]map[types.IdentityHash]*tecdsa.Round9P2P, len(participants))
	for i := range participants {
		round8UnicastOutputs[i], err = participants[i].Round9(round8UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round8UnicastOutputs, nil
}

func DoDkgRound10(participants []*tecdsa.Participant, round9UnicastInputs []map[types.IdentityHash]*tecdsa.Round9P2P) (round9UnicastOutputs []map[types.IdentityHash]*tecdsa.Round10P2P, err error) {
	round9UnicastOutputs = make([]map[types.IdentityHash]*tecdsa.Round10P2P, len(participants))
	for i := range participants {
		round9UnicastOutputs[i], err = participants[i].Round10(round9UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round9UnicastOutputs, nil
}

func DoDkgRound11(participants []*tecdsa.Participant, round10UnicastInputs []map[types.IdentityHash]*tecdsa.Round10P2P) (round10UnicastOutputs []map[types.IdentityHash]*tecdsa.Round11P2P, err error) {
	round10UnicastOutputs = make([]map[types.IdentityHash]*tecdsa.Round11P2P, len(participants))
	for i := range participants {
		round10UnicastOutputs[i], err = participants[i].Round11(round10UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round10UnicastOutputs, nil
}

func MapDkgRound[K any](participants []*tecdsa.Participant, round10UnicastOutputs []map[types.IdentityHash]*K) (round11UnicastInputs []map[types.IdentityHash]*K) {
	round11UnicastInputs = make([]map[types.IdentityHash]*K, len(participants))
	for i := range participants {
		round11UnicastInputs[i] = make(map[types.IdentityHash]*K)
		for j := range participants {
			if j != i {
				round11UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round10UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}
	return round11UnicastInputs
}

func DoDkgRound12(participants []*tecdsa.Participant, round11UnicastInputs []map[types.IdentityHash]*tecdsa.Round11P2P) (shards []*tecdsa.Shard, err error) {
	shards = make([]*tecdsa.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round12(round11UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}

	return shards, nil
}
