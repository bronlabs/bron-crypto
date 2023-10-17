package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	frost_noninteractive_signing "github.com/copperexchange/krypton-primitives/pkg/krypton/noninteractive_signing/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	signing_helpers "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/signing"
)

func MakeInteractiveSignParticipants(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*frost.Shard) (participants []*signing_helpers.Cosigner, err error) {
	if len(identities) < cohortConfig.Protocol.Threshold {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.Threshold)
	}

	participants = make([]*signing_helpers.Cosigner, cohortConfig.Protocol.Threshold)
	for i, identity := range identities {
		if !cohortConfig.IsInCohort(identity) {
			return nil, errs.NewMissing("invalid identity")
		}
		// TODO: test for what happens if session participants are set to be different for different parties
		participants[i], err = signing_helpers.NewInteractiveCosigner(identity, hashset.NewHashSet(identities), shards[i], cohortConfig, crand.Reader)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func MakeNonInteractiveCosigners(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*frost.Shard, preSignatureBatch *frost_noninteractive_signing.PreSignatureBatch, firstUnusedPreSignatureIndex []int, privateNoncePairsOfAllParties [][]*frost_noninteractive_signing.PrivateNoncePair) (participants []*frost_noninteractive_signing.Cosigner, err error) {
	participants = make([]*frost_noninteractive_signing.Cosigner, cohortConfig.Protocol.TotalParties)
	for i, identity := range identities {
		participants[i], err = frost_noninteractive_signing.NewNonInteractiveCosigner(identity, shards[i], preSignatureBatch, firstUnusedPreSignatureIndex[i], privateNoncePairsOfAllParties[i], hashset.NewHashSet(identities), cohortConfig, crand.Reader)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}
	return participants, nil
}

func DoInteractiveSignRound1(participants []*signing_helpers.Cosigner) (round1Outputs []*signing_helpers.Round1Broadcast, err error) {
	round1Outputs = make([]*signing_helpers.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 1")
		}
	}

	return round1Outputs, nil
}

func DoInteractiveSignRound2(participants []*signing_helpers.Cosigner, round2Inputs []map[types.IdentityHash]*signing_helpers.Round1Broadcast, message []byte) (partialSignatures []*frost.PartialSignature, err error) {
	partialSignatures = make([]*frost.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round2(round2Inputs[i], message)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 2")
		}
	}

	return partialSignatures, nil
}

func MapPartialSignatures(identities []integration.IdentityKey, partialSignatures []*frost.PartialSignature) map[types.IdentityHash]*frost.PartialSignature {
	result := make(map[types.IdentityHash]*frost.PartialSignature)
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
			return nil, errs.WrapFailed(err, "could not run DKG round 2")
		}
	}

	return partialSignatures, nil
}
