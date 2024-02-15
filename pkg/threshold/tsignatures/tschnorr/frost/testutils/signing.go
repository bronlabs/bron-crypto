package testutils

import (
	crand "crypto/rand"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	signing_helpers "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/noninteractive_signing"
)

func MakeInteractiveSignParticipants(protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards []*frost.Shard) (participants []*signing_helpers.Cosigner, err error) {
	if len(identities) < int(protocol.Threshold()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.Threshold())
	}

	participants = make([]*signing_helpers.Cosigner, protocol.Threshold())
	for i, identity := range identities {
		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("invalid identity")
		}
		participants[i], err = signing_helpers.NewInteractiveCosigner(identity.(types.AuthKey), hashset.NewHashableHashSet(identities...), shards[i], protocol, crand.Reader)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func MakeNonInteractiveCosigners(protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards []*frost.Shard, preSignatureBatch noninteractive_signing.PreSignatureBatch, firstUnusedPreSignatureIndex []int, privateNoncePairsOfAllParties [][]*noninteractive_signing.PrivateNoncePair) (participants []*noninteractive_signing.Cosigner, err error) {
	participants = make([]*noninteractive_signing.Cosigner, protocol.TotalParties())
	for i, identity := range identities {
		participants[i], err = noninteractive_signing.NewNonInteractiveCosigner(identity.(types.AuthKey), shards[i], preSignatureBatch, firstUnusedPreSignatureIndex[i], privateNoncePairsOfAllParties[i], hashset.NewHashableHashSet(identities...), protocol, hashset.NewHashableHashSet(identities...), crand.Reader)
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
			return nil, errs.WrapFailed(err, "could not run sign round 1")
		}
	}

	return round1Outputs, nil
}

func DoInteractiveSignRound2(participants []*signing_helpers.Cosigner, round2Inputs []types.RoundMessages[*signing_helpers.Round1Broadcast], message []byte) (partialSignatures []*frost.PartialSignature, err error) {
	partialSignatures = make([]*frost.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round2(round2Inputs[i], message)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run sign round 2")
		}
	}

	return partialSignatures, nil
}

func MapPartialSignatures(identities []types.IdentityKey, partialSignatures []*frost.PartialSignature) ds.HashMap[types.IdentityKey, *frost.PartialSignature] {
	result := hashmap.NewHashableHashMap[types.IdentityKey, *frost.PartialSignature]()
	for i, identity := range identities {
		result.Put(identity, partialSignatures[i])
	}

	return result
}

func DoProducePartialSignature(participants []*noninteractive_signing.Cosigner, message []byte) (partialSignatures []*frost.PartialSignature, err error) {
	partialSignatures = make([]*frost.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.ProducePartialSignature(message)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce partial signature")
		}
	}

	return partialSignatures, nil
}
