package test_utils

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	lindell17_dkg "github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/keygen/dkg"
	"github.com/pkg/errors"
	"io"
)

func MakeParticipants(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares, prngs []io.Reader) (participants []*lindell17_dkg.Participant, err error) {
	if len(identities) != cohortConfig.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.TotalParties)
	}

	participants = make([]*lindell17_dkg.Participant, cohortConfig.TotalParties)
	for i, identity := range identities {
		var prng io.Reader
		if prngs != nil && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("given test identity not in cohort (problem in tests?)")
		}
		participants[i], err = lindell17_dkg.NewBackupParticipant(identity, signingShares[i], publicKeyShares[i], cohortConfig, prng, sid, nil)
	}

	return participants, nil
}

func DoDkgRound1(participants []*lindell17_dkg.Participant) (round1BroadcastOutputs []*lindell17_dkg.Round1Broadcast, err error) {
	round1BroadcastOutputs = make([]*lindell17_dkg.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1BroadcastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*lindell17_dkg.Participant, round1BroadcastOutputs []*lindell17_dkg.Round1Broadcast) (round2BroadcastInputs []map[integration.IdentityKey]*lindell17_dkg.Round1Broadcast) {
	round2BroadcastInputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey()] = round1BroadcastOutputs[j]
			}
		}
	}

	return round2BroadcastInputs
}

func DoDkgRound2(participants []*lindell17_dkg.Participant, round2BroadcastInputs []map[integration.IdentityKey]*lindell17_dkg.Round1Broadcast) (round2Outputs []*lindell17_dkg.Round2Broadcast, err error) {
	round2Outputs = make([]*lindell17_dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*lindell17_dkg.Participant, round2Outputs []*lindell17_dkg.Round2Broadcast) (round3Inputs []map[integration.IdentityKey]*lindell17_dkg.Round2Broadcast) {
	round3Inputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].GetIdentityKey()] = round2Outputs[j]
			}
		}
	}

	return round3Inputs
}

func DoDkgRound3(participants []*lindell17_dkg.Participant, round3Inputs []map[integration.IdentityKey]*lindell17_dkg.Round2Broadcast) (round3Outputs []*lindell17_dkg.Round3Broadcast, err error) {
	round3Outputs = make([]*lindell17_dkg.Round3Broadcast, len(participants))
	for i := range participants {
		round3Outputs[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round3Outputs, nil
}

func MapDkgRound3OutputsToRound4Inputs(participants []*lindell17_dkg.Participant, round3Outputs []*lindell17_dkg.Round3Broadcast) (round4Inputs []map[integration.IdentityKey]*lindell17_dkg.Round3Broadcast) {
	round4Inputs = make([]map[integration.IdentityKey]*lindell17_dkg.Round3Broadcast, len(participants))
	for i := range participants {
		round4Inputs[i] = make(map[integration.IdentityKey]*lindell17_dkg.Round3Broadcast)
		for j := range participants {
			if j != i {
				round4Inputs[i][participants[j].GetIdentityKey()] = round3Outputs[j]
			}
		}
	}

	return round4Inputs
}

func DoDkgRound4(participants []*lindell17_dkg.Participant, round4Inputs []map[integration.IdentityKey]*lindell17_dkg.Round3Broadcast) (shards []*lindell17.Shard, err error) {
	shards = make([]*lindell17.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round4(round4Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return shards, nil
}
