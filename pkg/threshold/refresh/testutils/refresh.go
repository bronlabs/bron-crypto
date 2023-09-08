package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/pkg/errors"

	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/threshold/refresh"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures"
)

func MakeParticipants(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, prngs []io.Reader) (participants []*refresh.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*refresh.Participant, cohortConfig.Protocol.TotalParties)
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

		participants[i], err = refresh.NewParticipant(uniqueSessionId, identity, signingKeyShares[i], publicKeyShares[i], cohortConfig, nil, prng)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*refresh.Participant) (round1BroadcastOutputs []*refresh.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*refresh.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*refresh.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[types.IdentityHash]*refresh.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, err
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*refresh.Participant, round1BroadcastOutputs []*refresh.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*refresh.Round1P2P) (round2BroadcastInputs []map[types.IdentityHash]*refresh.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*refresh.Round1P2P) {
	round2BroadcastInputs = make([]map[types.IdentityHash]*refresh.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[types.IdentityHash]*refresh.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round1BroadcastOutputs[j]
			}
		}
	}

	round2UnicastInputs = make([]map[types.IdentityHash]*refresh.Round1P2P, len(participants))
	for i := range participants {
		round2UnicastInputs[i] = make(map[types.IdentityHash]*refresh.Round1P2P)
		for j := range participants {
			if j != i {
				round2UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round1UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round2BroadcastInputs, round2UnicastInputs
}

func DoDkgRound2(participants []*refresh.Participant, round2BroadcastInputs []map[types.IdentityHash]*refresh.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*refresh.Round1P2P) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, err error) {
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

func RunRefresh(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, initialSigningKeyShares []*tsignatures.SigningKeyShare, initialPublicKeyShares []*tsignatures.PublicKeyShares) (participants []*refresh.Participant, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, err error) {
	participants, err = MakeParticipants(sid, cohortConfig, identities, initialSigningKeyShares, initialPublicKeyShares, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoDkgRound1(participants)
	if err != nil {
		return nil, nil, nil, err
	}

	r2InsB, r2InsU := MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	signingKeyShares, publicKeyShares, err = DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, nil, err
	}
	return participants, signingKeyShares, publicKeyShares, nil
}
