package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/pkg/errors"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/keygen/dkg"
)

func MakeDkgParticipants(curve curves.Curve, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader, sid []byte) (participants []*dkg.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*dkg.Participant, cohortConfig.Protocol.TotalParties)

	if len(sid) == 0 {
		sid, err = agreeonrandom_testutils.ProduceSharedRandomValue(curve, identities, crand.Reader)
		if err != nil {
			return nil, err
		}
	}

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

		participants[i], err = dkg.NewParticipant(sid, identity, cohortConfig, prng, nil)
		if err != nil {
			return nil, err
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

func DoDkgRound2(participants []*dkg.Participant, round2BroadcastInputs []map[types.IdentityHash]*dkg.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*dkg.Round1P2P) (round2BroadcastOutputs []*dkg.Round2Broadcast, round2UnicastOutputs []map[types.IdentityHash]*dkg.Round2P2P, err error) {
	round2BroadcastOutputs = make([]*dkg.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]map[types.IdentityHash]*dkg.Round2P2P, len(participants))
	for i := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*dkg.Participant, round2BroadcastOutputs []*dkg.Round2Broadcast, round2UnicastOutputs []map[types.IdentityHash]*dkg.Round2P2P) (round3BroadcastInputs []map[types.IdentityHash]*dkg.Round2Broadcast, round3UnicastInputs []map[types.IdentityHash]*dkg.Round2P2P) {
	round3BroadcastInputs = make([]map[types.IdentityHash]*dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = make(map[types.IdentityHash]*dkg.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round2BroadcastOutputs[j]
			}
		}
	}
	round3UnicastInputs = make([]map[types.IdentityHash]*dkg.Round2P2P, len(participants))
	for i := range participants {
		round3UnicastInputs[i] = make(map[types.IdentityHash]*dkg.Round2P2P)
		for j := range participants {
			if j != i {
				round3UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round2UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round3BroadcastInputs, round3UnicastInputs
}

func DoDkgRound3(participants []*dkg.Participant, round3BroadcastInputs []map[types.IdentityHash]*dkg.Round2Broadcast, round3UnicastInputs []map[types.IdentityHash]*dkg.Round2P2P) (round3UnicastOutputs []map[types.IdentityHash]dkg.Round3P2P, err error) {
	round3UnicastOutputs = make([]map[types.IdentityHash]dkg.Round3P2P, len(participants))
	for i := range participants {
		round3UnicastOutputs[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}

	return round3UnicastOutputs, nil
}

func MapDkgRound3OutputsToRound4Inputs(participants []*dkg.Participant, round3UnicastOutputs []map[types.IdentityHash]dkg.Round3P2P) (round4UnicastInputs []map[types.IdentityHash]dkg.Round3P2P) {
	round4UnicastInputs = make([]map[types.IdentityHash]dkg.Round3P2P, len(participants))
	for i := range participants {
		round4UnicastInputs[i] = make(map[types.IdentityHash]dkg.Round3P2P)
		for j := range participants {
			if j != i {
				round4UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round3UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round4UnicastInputs
}

func DoDkgRound4(participants []*dkg.Participant, round4UnicastInputs []map[types.IdentityHash]dkg.Round3P2P) (round4UnicastOutputs []map[types.IdentityHash]dkg.Round4P2P, err error) {
	round4UnicastOutputs = make([]map[types.IdentityHash]dkg.Round4P2P, len(participants))
	for i := range participants {
		round4UnicastOutputs[i], err = participants[i].Round4(round4UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}

	return round4UnicastOutputs, nil
}

func MapDkgRound4OutputsToRound5Inputs(participants []*dkg.Participant, round4UnicastOutputs []map[types.IdentityHash]dkg.Round4P2P) (round5UnicastInputs []map[types.IdentityHash]dkg.Round4P2P) {
	round5UnicastInputs = make([]map[types.IdentityHash]dkg.Round4P2P, len(participants))
	for i := range participants {
		round5UnicastInputs[i] = make(map[types.IdentityHash]dkg.Round4P2P)
		for j := range participants {
			if j != i {
				round5UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round4UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round5UnicastInputs
}

func DoDkgRound5(participants []*dkg.Participant, round5UnicastInputs []map[types.IdentityHash]dkg.Round4P2P) (round5UnicastOutputs []map[types.IdentityHash]dkg.Round5P2P, err error) {
	round5UnicastOutputs = make([]map[types.IdentityHash]dkg.Round5P2P, len(participants))
	for i := range participants {
		round5UnicastOutputs[i], err = participants[i].Round5(round5UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}

	return round5UnicastOutputs, nil
}

func MapDkgRound5OutputsToRound6Inputs(participants []*dkg.Participant, round5UnicastOutputs []map[types.IdentityHash]dkg.Round5P2P) (round6UnicastInputs []map[types.IdentityHash]dkg.Round5P2P) {
	round6UnicastInputs = make([]map[types.IdentityHash]dkg.Round5P2P, len(participants))
	for i := range participants {
		round6UnicastInputs[i] = make(map[types.IdentityHash]dkg.Round5P2P)
		for j := range participants {
			if j != i {
				round6UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round5UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round6UnicastInputs
}

func DoDkgRound6(participants []*dkg.Participant, round6UnicastInputs []map[types.IdentityHash]dkg.Round5P2P) (shards []*dkls23.Shard, err error) {
	shards = make([]*dkls23.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round6(round6UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}

	return shards, nil
}

func RunDKG(curve curves.Curve, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey) (shards []*dkls23.Shard, err error) {
	participants, err := MakeDkgParticipants(curve, cohortConfig, identities, nil, nil)
	if err != nil {
		return nil, err
	}

	r1OutsB, r1OutsU, err := DoDkgRound1(participants)
	if err != nil {
		return nil, err
	}

	r2InsB, r2InsU := MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2OutsB, r2OutsU, err := DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, err
	}

	r3InsB, r3InsU := MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	r3OutsU, err := DoDkgRound3(participants, r3InsB, r3InsU)
	if err != nil {
		return nil, err
	}

	r4InsU := MapDkgRound3OutputsToRound4Inputs(participants, r3OutsU)
	r4OutsU, err := DoDkgRound4(participants, r4InsU)
	if err != nil {
		return nil, err
	}

	r5InsU := MapDkgRound4OutputsToRound5Inputs(participants, r4OutsU)
	r5OutsU, err := DoDkgRound5(participants, r5InsU)
	if err != nil {
		return nil, err
	}

	r6InsU := MapDkgRound5OutputsToRound6Inputs(participants, r5OutsU)
	shards, err = DoDkgRound6(participants, r6InsU)
	if err != nil {
		return nil, err
	}

	return shards, nil
}
