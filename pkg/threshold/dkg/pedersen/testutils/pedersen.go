package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/pkg/errors"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
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

		participants[i], err = pedersen.NewParticipant(uniqueSessionId, identity, cohortConfig, nil, prng)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*pedersen.Participant, a_i0s []curves.Scalar) (round1BroadcastOutputs []*pedersen.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*pedersen.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*pedersen.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[types.IdentityHash]*pedersen.Round1P2P, len(participants))
	for i, participant := range participants {
		var a_i0 curves.Scalar
		if a_i0s == nil {
			a_i0 = nil
		} else {
			a_i0 = a_i0s[i]
		}
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1(a_i0)
		if err != nil {
			return nil, nil, err
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*pedersen.Participant, round1BroadcastOutputs []*pedersen.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*pedersen.Round1P2P) (round2BroadcastInputs []map[types.IdentityHash]*pedersen.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*pedersen.Round1P2P) {
	round2BroadcastInputs = make([]map[types.IdentityHash]*pedersen.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[types.IdentityHash]*pedersen.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round1BroadcastOutputs[j]
			}
		}
	}

	round2UnicastInputs = make([]map[types.IdentityHash]*pedersen.Round1P2P, len(participants))
	for i := range participants {
		round2UnicastInputs[i] = make(map[types.IdentityHash]*pedersen.Round1P2P)
		for j := range participants {
			if j != i {
				round2UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round1UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round2BroadcastInputs, round2UnicastInputs
}

func DoDkgRound2(participants []*pedersen.Participant, round2BroadcastInputs []map[types.IdentityHash]*pedersen.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*pedersen.Round1P2P) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, err error) {
	signingKeyShares = make([]*tsignatures.SigningKeyShare, len(participants))
	publicKeyShares = make([]*tsignatures.PublicKeyShares, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return signingKeyShares, publicKeyShares, nil
}
