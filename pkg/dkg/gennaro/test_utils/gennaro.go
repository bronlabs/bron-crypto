package test_utils

import (
	crand "crypto/rand"
	"io"

	"github.com/pkg/errors"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/dkg/gennaro"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

func MakeParticipants(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*gennaro.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*gennaro.Participant, cohortConfig.Protocol.TotalParties)
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
		participants[i], err = gennaro.NewParticipant(uniqueSessionId, identity, cohortConfig, prng, nil)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*gennaro.Participant) (round1BroadcastOutputs []*gennaro.Round1Broadcast, round1UnicastOutputs []map[helper_types.IdentityHash]*gennaro.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*gennaro.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[helper_types.IdentityHash]*gennaro.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, err
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*gennaro.Participant, round1BroadcastOutputs []*gennaro.Round1Broadcast, round1UnicastOutputs []map[helper_types.IdentityHash]*gennaro.Round1P2P) (round2BroadcastInputs []map[helper_types.IdentityHash]*gennaro.Round1Broadcast, round2UnicastInputs []map[helper_types.IdentityHash]*gennaro.Round1P2P) {
	round2BroadcastInputs = make([]map[helper_types.IdentityHash]*gennaro.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[helper_types.IdentityHash]*gennaro.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round1BroadcastOutputs[j]
			}
		}
	}

	round2UnicastInputs = make([]map[helper_types.IdentityHash]*gennaro.Round1P2P, len(participants))
	for i := range participants {
		round2UnicastInputs[i] = make(map[helper_types.IdentityHash]*gennaro.Round1P2P)
		for j := range participants {
			if j != i {
				round2UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round1UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round2BroadcastInputs, round2UnicastInputs
}

func DoDkgRound2(participants []*gennaro.Participant, round2BroadcastInputs []map[helper_types.IdentityHash]*gennaro.Round1Broadcast, round2UnicastInputs []map[helper_types.IdentityHash]*gennaro.Round1P2P) (round2Outputs []*gennaro.Round2Broadcast, err error) {
	round2Outputs = make([]*gennaro.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*gennaro.Participant, round3Outputs []*gennaro.Round2Broadcast) (round3Inputs []map[helper_types.IdentityHash]*gennaro.Round2Broadcast) {
	round3Inputs = make([]map[helper_types.IdentityHash]*gennaro.Round2Broadcast, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[helper_types.IdentityHash]*gennaro.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].GetIdentityKey().Hash()] = round3Outputs[j]
			}
		}
	}

	return round3Inputs
}

func DoDkgRound3(participants []*gennaro.Participant, round3Inputs []map[helper_types.IdentityHash]*gennaro.Round2Broadcast) (signingKeyShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares, err error) {
	signingKeyShares = make([]*threshold.SigningKeyShare, len(participants))
	publicKeyShares = make([]*threshold.PublicKeyShares, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return signingKeyShares, publicKeyShares, nil
}
