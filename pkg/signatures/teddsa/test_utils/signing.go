package test_utils

import (
	crand "crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	interactive_signing "github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/interactive"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/noninteractive"
	"github.com/pkg/errors"
)

func MakeInteractiveSignParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*frost.SigningKeyShare, publicKeyShares []*frost.PublicKeyShares) (participants []*interactive_signing.InteractiveCosigner, err error) {
	if len(identities) < cohortConfig.Threshold {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Threshold)
	}

	participants = make([]*interactive_signing.InteractiveCosigner, cohortConfig.Threshold)
	for i, identity := range identities {
		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("invalid identity")
		}
		participants[i], err = interactive_signing.NewInteractiveCosigner(identity, identities, signingKeyShares[i], publicKeyShares[i], cohortConfig, crand.Reader)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func MakeNonInteractiveCosigners(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*frost.SigningKeyShare, publicKeySharesOfAllParties []*frost.PublicKeyShares, preSignatureBatch *noninteractive.PreSignatureBatch, lastUsedPreSignatureIndices []int, privateNoncePairsOfAllParties [][]*noninteractive.PrivateNoncePair) (participants []*noninteractive.NonInteractiveCosigner, err error) {
	// copy identities as they get sorted inplace when creating participant
	// identitiesCopy := make([]integration.IdentityKey, cohortConfig.TotalParties)
	// copy(identitiesCopy, cohortConfig.Participants)

	participants = make([]*noninteractive.NonInteractiveCosigner, cohortConfig.TotalParties)
	for i, identity := range identities {
		participants[i], err = noninteractive.NewNonInteractiveCosigner(identity, signingKeyShares[i], publicKeySharesOfAllParties[i], preSignatureBatch, lastUsedPreSignatureIndices[i], privateNoncePairsOfAllParties[i], identities, cohortConfig, crand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoInteractiveSignRound1(participants []*interactive_signing.InteractiveCosigner) (round1Outputs []*interactive_signing.Round1Broadcast, err error) {
	round1Outputs = make([]*interactive_signing.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1Outputs, nil
}

func MapInteractiveSignRound1OutputsToRound2Inputs(participants []*interactive_signing.InteractiveCosigner, round1Outputs []*interactive_signing.Round1Broadcast) (round2Inputs []map[integration.IdentityKey]*interactive_signing.Round1Broadcast) {
	round2Inputs = make([]map[integration.IdentityKey]*interactive_signing.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityKey]*interactive_signing.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey] = round1Outputs[j]
			}
		}
	}

	return round2Inputs
}

func DoInteractiveSignRound2(participants []*interactive_signing.InteractiveCosigner, round2Inputs []map[integration.IdentityKey]*interactive_signing.Round1Broadcast, message []byte) (partialSignatures []*frost.PartialSignature, err error) {
	partialSignatures = make([]*frost.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round2(round2Inputs[i], message)
		if err != nil {
			return nil, err
		}
	}

	return partialSignatures, nil
}

func MapPartialSignatures(identities []integration.IdentityKey, partialSignatures []*frost.PartialSignature) map[integration.IdentityKey]*frost.PartialSignature {
	result := make(map[integration.IdentityKey]*frost.PartialSignature)
	for i, identity := range identities {
		result[identity] = partialSignatures[i]
	}

	return result
}

func DoProducePartialSignature(participants []*noninteractive.NonInteractiveCosigner, message []byte) (partialSignatures []*frost.PartialSignature, indices []int, err error) {
	partialSignatures = make([]*frost.PartialSignature, len(participants))
	indices = make([]int, len(participants))
	for i, participant := range participants {
		partialSignatures[i], indices[i], err = participant.ProducePartialSignature(message)
		if err != nil {
			return nil, nil, err
		}
	}

	return partialSignatures, indices, nil
}
