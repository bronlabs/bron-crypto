package test_utils

import (
	crand "crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/noninteractive"
)

func MakeNonInteractiveCosigners(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*frost.SigningKeyShare, publicKeySharesOfAllParties []*frost.PublicKeyShares, preSignatureBatch *noninteractive.PreSignatureBatch, lastUsedPreSignatureIndices []int, privateNoncePairsOfAllParties [][]*noninteractive.PrivateNoncePair) (participants []*noninteractive.NonInteractiveCosigner, err error) {
	// copy identities as they get sorted inplace when creating participant
	identitiesCopy := make([]integration.IdentityKey, cohortConfig.TotalParties)
	copy(identitiesCopy, cohortConfig.Participants)
	integration.SortIdentityKeysInPlace(identitiesCopy)

	participants = make([]*noninteractive.NonInteractiveCosigner, cohortConfig.TotalParties)
	for i, identity := range identitiesCopy {
		participants[i], err = noninteractive.NewNonInteractiveCosigner(identity, signingKeyShares[i], publicKeySharesOfAllParties[i], preSignatureBatch, lastUsedPreSignatureIndices[i], privateNoncePairsOfAllParties[i], identities, cohortConfig, crand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
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

func MapPartialSignatures(participants []*noninteractive.NonInteractiveCosigner, partialSignatures []*frost.PartialSignature) map[integration.IdentityKey]*frost.PartialSignature {
	result := make(map[integration.IdentityKey]*frost.PartialSignature)
	for i, participant := range participants {
		result[participant.MyIdentityKey] = partialSignatures[i]
	}

	return result
}
