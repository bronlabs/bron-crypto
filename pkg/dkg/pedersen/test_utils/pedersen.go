package test_utils

import (
	crand "crypto/rand"

	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen"
	"github.com/pkg/errors"
)

func MakeParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*pedersen.Participant, err error) {
	if len(identities) != cohortConfig.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.TotalParties)
	}

	participants = make([]*pedersen.Participant, cohortConfig.TotalParties)
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

		participants[i], err = pedersen.NewParticipant(identity, cohortConfig, prng)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*pedersen.Participant) (round1Outputs []*pedersen.Round1Broadcast, err error) {
	round1Outputs = make([]*pedersen.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1Outputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*pedersen.Participant, round1Outputs []*pedersen.Round1Broadcast) (round2Inputs []map[integration.IdentityKey]*pedersen.Round1Broadcast) {
	round2Inputs = make([]map[integration.IdentityKey]*pedersen.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityKey]*pedersen.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].GetIdentityKey()] = round1Outputs[j]
			}
		}
	}

	return round2Inputs
}

func DoDkgRound2(participants []*pedersen.Participant, round2Inputs []map[integration.IdentityKey]*pedersen.Round1Broadcast) (round2BroadcastOutputs []*pedersen.Round2Broadcast, round2UnicastOutputs []map[integration.IdentityKey]*pedersen.Round2P2P, err error) {
	round2BroadcastOutputs = make([]*pedersen.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]map[integration.IdentityKey]*pedersen.Round2P2P, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*pedersen.Participant, round2BroadcastOutputs []*pedersen.Round2Broadcast, round2UnicastOutputs []map[integration.IdentityKey]*pedersen.Round2P2P) (round3BroadcastInputs []map[integration.IdentityKey]*pedersen.Round2Broadcast, round3UnicastInputs []map[integration.IdentityKey]*pedersen.Round2P2P) {
	round3BroadcastInputs = make([]map[integration.IdentityKey]*pedersen.Round2Broadcast, len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = make(map[integration.IdentityKey]*pedersen.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3BroadcastInputs[i][participants[j].GetIdentityKey()] = round2BroadcastOutputs[j]
			}
		}
	}

	round3UnicastInputs = make([]map[integration.IdentityKey]*pedersen.Round2P2P, len(participants))
	for i := range participants {
		round3UnicastInputs[i] = make(map[integration.IdentityKey]*pedersen.Round2P2P)
		for j := range participants {
			if j != i {
				round3UnicastInputs[i][participants[j].GetIdentityKey()] = round2UnicastOutputs[j][participants[i].GetIdentityKey()]
			}
		}
	}

	return round3BroadcastInputs, round3UnicastInputs
}

func DoDkgRound3(participants []*pedersen.Participant, round3BroadcastInputs []map[integration.IdentityKey]*pedersen.Round2Broadcast, round3UnicastInputs []map[integration.IdentityKey]*pedersen.Round2P2P) (signingKeyShares []*integration.SigningKeyShare, publicKeyShares []*integration.PublicKeyShares, err error) {
	signingKeyShares = make([]*integration.SigningKeyShare, len(participants))
	publicKeyShares = make([]*integration.PublicKeyShares, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return signingKeyShares, publicKeyShares, nil
}
