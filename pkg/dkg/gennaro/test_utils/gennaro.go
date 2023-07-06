package test_utils

import (
	crand "crypto/rand"

	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/gennaro"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
	"github.com/pkg/errors"
)

func MakeParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*gennaro.Participant, err error) {
	if len(identities) != cohortConfig.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.TotalParties)
	}

	participants = make([]*gennaro.Participant, cohortConfig.TotalParties)
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

		participants[i], err = gennaro.NewParticipant(identity, cohortConfig, prng, nil)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*gennaro.Participant) (round1Outputs []*gennaro.Round1Broadcast, err error) {
	round1Outputs = make([]*gennaro.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1Outputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*gennaro.Participant, round1Outputs []*gennaro.Round1Broadcast) (round2Inputs []map[integration.IdentityKey]*gennaro.Round1Broadcast) {
	round2Inputs = make([]map[integration.IdentityKey]*gennaro.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityKey]*gennaro.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].GetIdentityKey()] = round1Outputs[j]
			}
		}
	}

	return round2Inputs
}

func DoDkgRound2(participants []*gennaro.Participant, round2Inputs []map[integration.IdentityKey]*gennaro.Round1Broadcast) (round2BroadcastOutputs []*gennaro.Round2Broadcast, round2UnicastOutputs []map[integration.IdentityKey]*gennaro.Round2P2P, err error) {
	round2BroadcastOutputs = make([]*gennaro.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]map[integration.IdentityKey]*gennaro.Round2P2P, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*gennaro.Participant, round2BroadcastOutputs []*gennaro.Round2Broadcast, round2UnicastOutputs []map[integration.IdentityKey]*gennaro.Round2P2P) (round3BroadcastInputs []map[integration.IdentityKey]*gennaro.Round2Broadcast, round3UnicastInputs []map[integration.IdentityKey]*gennaro.Round2P2P) {
	round3BroadcastInputs = make([]map[integration.IdentityKey]*gennaro.Round2Broadcast, len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = make(map[integration.IdentityKey]*gennaro.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3BroadcastInputs[i][participants[j].GetIdentityKey()] = round2BroadcastOutputs[j]
			}
		}
	}

	round3UnicastInputs = make([]map[integration.IdentityKey]*gennaro.Round2P2P, len(participants))
	for i := range participants {
		round3UnicastInputs[i] = make(map[integration.IdentityKey]*gennaro.Round2P2P)
		for j := range participants {
			if j != i {
				round3UnicastInputs[i][participants[j].GetIdentityKey()] = round2UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round3BroadcastInputs, round3UnicastInputs
}

func DoDkgRound3(participants []*gennaro.Participant, round3BroadcastInputs []map[integration.IdentityKey]*gennaro.Round2Broadcast, round3UnicastInputs []map[integration.IdentityKey]*gennaro.Round2P2P) (round3Outputs []*gennaro.Round3Broadcast, err error) {
	round3Outputs = make([]*gennaro.Round3Broadcast, len(participants))
	for i := range participants {
		round3Outputs[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round3Outputs, nil
}

func MapDkgRound3OutputsToRound4Inputs(participants []*gennaro.Participant, round3Outputs []*gennaro.Round3Broadcast) (round4Inputs []map[integration.IdentityKey]*gennaro.Round3Broadcast) {
	round4Inputs = make([]map[integration.IdentityKey]*gennaro.Round3Broadcast, len(participants))
	for i := range participants {
		round4Inputs[i] = make(map[integration.IdentityKey]*gennaro.Round3Broadcast)
		for j := range participants {
			if j != i {
				round4Inputs[i][participants[j].GetIdentityKey()] = round3Outputs[j]
			}
		}
	}

	return round4Inputs
}

func DoDkgRound4(participants []*gennaro.Participant, round4Inputs []map[integration.IdentityKey]*gennaro.Round3Broadcast) (signingKeyShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares, err error) {
	signingKeyShares = make([]*threshold.SigningKeyShare, len(participants))
	publicKeyShares = make([]*threshold.PublicKeyShares, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round4(round4Inputs[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return signingKeyShares, publicKeyShares, nil
}
