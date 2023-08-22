package test_utils

import (
	crand "crypto/rand"
	"io"

	"github.com/pkg/errors"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/dkg/pedersen"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

func MakeParticipants(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*pedersen.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*pedersen.Participant, cohortConfig.Protocol.TotalParties)
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

		participants[i], err = pedersen.NewParticipant(uniqueSessionId, identity, cohortConfig, prng)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*pedersen.Participant) (round1BroadcastOutputs []*pedersen.Round1Broadcast, round1UnicastOutputs []map[helper_types.IdentityHash]*pedersen.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*pedersen.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[helper_types.IdentityHash]*pedersen.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, err
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*pedersen.Participant, round1BroadcastOutputs []*pedersen.Round1Broadcast, round1UnicastOutputs []map[helper_types.IdentityHash]*pedersen.Round1P2P) (round2BroadcastInputs []map[helper_types.IdentityHash]*pedersen.Round1Broadcast, round2UnicastInputs []map[helper_types.IdentityHash]*pedersen.Round1P2P) {
	round2BroadcastInputs = make([]map[helper_types.IdentityHash]*pedersen.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[helper_types.IdentityHash]*pedersen.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round1BroadcastOutputs[j]
			}
		}
	}

	round2UnicastInputs = make([]map[helper_types.IdentityHash]*pedersen.Round1P2P, len(participants))
	for i := range participants {
		round2UnicastInputs[i] = make(map[helper_types.IdentityHash]*pedersen.Round1P2P)
		for j := range participants {
			if j != i {
				round2UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round1UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round2BroadcastInputs, round2UnicastInputs
}

func DoDkgRound2(participants []*pedersen.Participant, round2BroadcastInputs []map[helper_types.IdentityHash]*pedersen.Round1Broadcast, round2UnicastInputs []map[helper_types.IdentityHash]*pedersen.Round1P2P) (signingKeyShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares, err error) {
	signingKeyShares = make([]*threshold.SigningKeyShare, len(participants))
	publicKeyShares = make([]*threshold.PublicKeyShares, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return signingKeyShares, publicKeyShares, nil
}
