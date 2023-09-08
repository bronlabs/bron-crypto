package test_utils

import (
	crand "crypto/rand"

	"github.com/pkg/errors"

	"github.com/copperexchange/knox-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	frost_noninteractive_signing "github.com/copperexchange/knox-primitives/pkg/knox/noninteractive_signing/tschnorr/frost"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	interactive_signing "github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tschnorr/frost/signing/interactive"
)

func MakeInteractiveSignParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*frost.Shard) (participants []*interactive_signing.Cosigner, err error) {
	if len(identities) < cohortConfig.Protocol.Threshold {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.Threshold)
	}

	participants = make([]*interactive_signing.Cosigner, cohortConfig.Protocol.Threshold)
	for i, identity := range identities {
		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("invalid identity")
		}
		// TODO: test for what happens if session participants are set to be different for different parties
		participants[i], err = interactive_signing.NewInteractiveCosigner(identity, hashset.NewHashSet(identities), shards[i], cohortConfig, crand.Reader)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func MakeNonInteractiveCosigners(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*frost.Shard, preSignatureBatch *frost_noninteractive_signing.PreSignatureBatch, firstUnusedPreSignatureIndex []int, privateNoncePairsOfAllParties [][]*frost_noninteractive_signing.PrivateNoncePair) (participants []*frost_noninteractive_signing.Cosigner, err error) {
	participants = make([]*frost_noninteractive_signing.Cosigner, cohortConfig.Protocol.TotalParties)
	for i, identity := range identities {
		participants[i], err = frost_noninteractive_signing.NewNonInteractiveCosigner(identity, shards[i], preSignatureBatch, firstUnusedPreSignatureIndex[i], privateNoncePairsOfAllParties[i], hashset.NewHashSet(identities), cohortConfig, crand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return participants, nil
}

func DoInteractiveSignRound1(participants []*interactive_signing.Cosigner) (round1Outputs []*interactive_signing.Round1Broadcast, err error) {
	round1Outputs = make([]*interactive_signing.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1Outputs, nil
}

func MapInteractiveSignRound1OutputsToRound2Inputs(participants []*interactive_signing.Cosigner, round1Outputs []*interactive_signing.Round1Broadcast) (round2Inputs []map[helper_types.IdentityHash]*interactive_signing.Round1Broadcast) {
	round2Inputs = make([]map[helper_types.IdentityHash]*interactive_signing.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[helper_types.IdentityHash]*interactive_signing.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey.Hash()] = round1Outputs[j]
			}
		}
	}

	return round2Inputs
}

func DoInteractiveSignRound2(participants []*interactive_signing.Cosigner, round2Inputs []map[helper_types.IdentityHash]*interactive_signing.Round1Broadcast, message []byte) (partialSignatures []*frost.PartialSignature, err error) {
	partialSignatures = make([]*frost.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round2(round2Inputs[i], message)
		if err != nil {
			return nil, err
		}
	}

	return partialSignatures, nil
}

func MapPartialSignatures(identities []integration.IdentityKey, partialSignatures []*frost.PartialSignature) map[helper_types.IdentityHash]*frost.PartialSignature {
	result := make(map[helper_types.IdentityHash]*frost.PartialSignature)
	for i, identity := range identities {
		result[identity.Hash()] = partialSignatures[i]
	}

	return result
}

func DoProducePartialSignature(participants []*frost_noninteractive_signing.Cosigner, message []byte) (partialSignatures []*frost.PartialSignature, err error) {
	partialSignatures = make([]*frost.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.ProducePartialSignature(message)
		if err != nil {
			return nil, err
		}
	}

	return partialSignatures, nil
}
