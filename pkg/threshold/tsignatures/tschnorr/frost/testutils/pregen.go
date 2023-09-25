package testutils

import (
	crand "crypto/rand"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/krypton/noninteractive_signing/tschnorr/frost"
)

func MakePreGenParticipants(cohortConfig *integration.CohortConfig, tau int) (participants []*frost.PreGenParticipant, err error) {
	// copy identities as they get sorted inplace when creating participant
	identities := cohortConfig.Participants.Clone()

	participants = make([]*frost.PreGenParticipant, cohortConfig.Protocol.TotalParties)
	sortedIdentities := integration.ByPublicKey(identities.List())
	sort.Sort(sortedIdentities)
	i := -1
	for _, identity := range sortedIdentities {
		i++
		participants[i], err = frost.NewPreGenParticipant(identity, cohortConfig, tau, crand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoPreGenRound1(participants []*frost.PreGenParticipant) (round1Outputs []*frost.Round1Broadcast, err error) {
	round1Outputs = make([]*frost.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1Outputs, nil
}

func MapPreGenRound1OutputsToRound2Inputs(participants []*frost.PreGenParticipant, round1Outputs []*frost.Round1Broadcast) (round2Inputs []map[types.IdentityHash]*frost.Round1Broadcast) {
	round2Inputs = make([]map[types.IdentityHash]*frost.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[types.IdentityHash]*frost.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey.Hash()] = round1Outputs[j]
			}
		}
	}

	return round2Inputs
}

func DoPreGenRound2(participants []*frost.PreGenParticipant, round2Inputs []map[types.IdentityHash]*frost.Round1Broadcast) ([]*frost.PreSignatureBatch, [][]*frost.PrivateNoncePair, error) {
	var err error
	preSignatures := make([]*frost.PreSignatureBatch, len(participants))
	privateNoncePairs := make([][]*frost.PrivateNoncePair, len(participants))
	for i, participant := range participants {

		preSignatures[i], privateNoncePairs[i], err = participant.Round2(round2Inputs[i])

		if err != nil {
			return nil, nil, err
		}
	}

	return preSignatures, privateNoncePairs, nil
}
