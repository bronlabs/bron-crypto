package test_utils

import (
	crand "crypto/rand"
	"sort"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing/noninteractive"
)

func MakePreGenParticipants(cohortConfig *integration.CohortConfig, tau int) (participants []*noninteractive.PreGenParticipant, err error) {
	// copy identities as they get sorted inplace when creating participant
	identities := cohortConfig.Participants.Clone()

	participants = make([]*noninteractive.PreGenParticipant, cohortConfig.TotalParties)
	sortedIdentities := integration.ByPublicKey(identities.List())
	sort.Sort(sortedIdentities)
	i := -1
	for _, identity := range sortedIdentities {
		i++
		participants[i], err = noninteractive.NewPreGenParticipant(identity, cohortConfig, tau, crand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoPreGenRound1(participants []*noninteractive.PreGenParticipant) (round1Outputs []*noninteractive.Round1Broadcast, err error) {
	round1Outputs = make([]*noninteractive.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1Outputs, nil
}

func MapPreGenRound1OutputsToRound2Inputs(participants []*noninteractive.PreGenParticipant, round1Outputs []*noninteractive.Round1Broadcast) (round2Inputs []map[helper_types.IdentityHash]*noninteractive.Round1Broadcast) {
	round2Inputs = make([]map[helper_types.IdentityHash]*noninteractive.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[helper_types.IdentityHash]*noninteractive.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey.Hash()] = round1Outputs[j]
			}
		}
	}

	return round2Inputs
}

func DoPreGenRound2(participants []*noninteractive.PreGenParticipant, round2Inputs []map[helper_types.IdentityHash]*noninteractive.Round1Broadcast) ([]*noninteractive.PreSignatureBatch, [][]*noninteractive.PrivateNoncePair, error) {
	var err error
	preSignatures := make([]*noninteractive.PreSignatureBatch, len(participants))
	privateNoncePairs := make([][]*noninteractive.PrivateNoncePair, len(participants))
	for i, participant := range participants {

		preSignatures[i], privateNoncePairs[i], err = participant.Round2(round2Inputs[i])

		if err != nil {
			return nil, nil, err
		}
	}

	return preSignatures, privateNoncePairs, nil
}
