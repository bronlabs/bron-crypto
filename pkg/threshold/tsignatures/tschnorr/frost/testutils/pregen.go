package testutils

import (
	crand "crypto/rand"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/noninteractive_signing"
)

func MakePreGenParticipants(cohortConfig *integration.CohortConfig, tau int) (participants []*noninteractive_signing.PreGenParticipant, err error) {
	// copy identities as they get sorted inplace when creating participant
	identities := cohortConfig.Participants.Clone()

	participants = make([]*noninteractive_signing.PreGenParticipant, cohortConfig.Protocol.TotalParties)
	sortedIdentities := integration.ByPublicKey(identities.List())
	sort.Sort(sortedIdentities)
	i := -1
	for _, identity := range sortedIdentities {
		i++
		participants[i], err = noninteractive_signing.NewPreGenParticipant(identity, cohortConfig, tau, crand.Reader)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}
	return participants, nil
}

func DoPreGenRound1(participants []*noninteractive_signing.PreGenParticipant) (round1Outputs []*noninteractive_signing.Round1Broadcast, err error) {
	round1Outputs = make([]*noninteractive_signing.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 1")
		}
	}

	return round1Outputs, nil
}

func DoPreGenRound2(participants []*noninteractive_signing.PreGenParticipant, round2Inputs []map[types.IdentityHash]*noninteractive_signing.Round1Broadcast) ([]*noninteractive_signing.PreSignatureBatch, [][]*noninteractive_signing.PrivateNoncePair, error) {
	var err error
	preSignatures := make([]*noninteractive_signing.PreSignatureBatch, len(participants))
	privateNoncePairs := make([][]*noninteractive_signing.PrivateNoncePair, len(participants))
	for i, participant := range participants {
		preSignatures[i], privateNoncePairs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run DKG round 2")
		}
	}

	return preSignatures, privateNoncePairs, nil
}
