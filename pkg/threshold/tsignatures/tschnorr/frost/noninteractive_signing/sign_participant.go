package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
)

var _ types.ThresholdSignatureParticipant = (*Cosigner)(nil)

type Cosigner struct {
	prng io.Reader

	PreSignatures                PreSignatureBatch
	FirstUnusedPreSignatureIndex int

	MyAuthKey            types.AuthKey
	MySharingId          types.SharingID
	Shard                *frost.Shard
	SignatureAggregators ds.HashSet[types.IdentityKey]

	Protocol            types.ThresholdSignatureProtocol
	SessionParticipants ds.HashSet[types.IdentityKey]
	SharingConfig       types.SharingConfig

	myPrivateNoncePairs []*PrivateNoncePair

	aggregationParameter *aggregation.SignatureAggregatorParameters

	_ ds.Incomparable
}

func (nic *Cosigner) AuthKey() types.AuthKey {
	return nic.MyAuthKey
}

func (nic *Cosigner) IdentityKey() types.IdentityKey {
	return nic.MyAuthKey
}

func (nic *Cosigner) SharingId() types.SharingID {
	return nic.MySharingId
}

func (nic *Cosigner) IsSignatureAggregator() bool {
	return nic.SignatureAggregators.Contains(nic.IdentityKey())
}

func NewNonInteractiveCosigner(
	authKey types.AuthKey, shard *frost.Shard,
	preSignatureBatch PreSignatureBatch, firstUnusedPreSignatureIndex int, privateNoncePairs []*PrivateNoncePair,
	presentParties ds.HashSet[types.IdentityKey], protocol types.ThresholdSignatureProtocol, signatureAggregators ds.HashSet[types.IdentityKey], prng io.Reader,
) (*Cosigner, error) {
	err := validateInputsNonInteractiveSigning(authKey, shard, preSignatureBatch, firstUnusedPreSignatureIndex, privateNoncePairs, presentParties, signatureAggregators, protocol, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}
	for i, privateNoncePair := range privateNoncePairs {
		preSignature := preSignatureBatch[i]
		myAttestedCommitment := (preSignature)[mySharingId-1]
		curve := myAttestedCommitment.D.Curve()
		if !curve.ScalarBaseMult(privateNoncePair.SmallD).Equal(myAttestedCommitment.D) {
			return nil, errs.NewFailed("my d nonce at index %d is not equal to the corresponding commitment", i)
		}
		if !curve.ScalarBaseMult(privateNoncePair.SmallE).Equal(myAttestedCommitment.E) {
			return nil, errs.NewFailed("my e nonce at index %d is not equal to the corresponding commitment", i)
		}
	}

	D_alpha := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	E_alpha := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	preSignature := preSignatureBatch[firstUnusedPreSignatureIndex]
	for _, attestedCommitment := range preSignature {
		if found := presentParties.Contains(attestedCommitment.Attestor); !found {
			continue
		}
		D_alpha.Put(attestedCommitment.Attestor, attestedCommitment.D)
		E_alpha.Put(attestedCommitment.Attestor, attestedCommitment.E)
	}

	participant := &Cosigner{
		prng:                         prng,
		PreSignatures:                preSignatureBatch,
		FirstUnusedPreSignatureIndex: firstUnusedPreSignatureIndex,
		MyAuthKey:                    authKey,
		MySharingId:                  mySharingId,
		Shard:                        shard,
		Protocol:                     protocol,
		SharingConfig:                sharingConfig,
		SignatureAggregators:         signatureAggregators,
		SessionParticipants:          presentParties,
		myPrivateNoncePairs:          privateNoncePairs,
		aggregationParameter: &aggregation.SignatureAggregatorParameters{
			D_alpha: D_alpha,
			E_alpha: E_alpha,
		},
	}

	if err := types.ValidateThresholdSignatureProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct non interactive participant")
	}

	return participant, nil
}

func validateInputsNonInteractiveSigning(authKey types.AuthKey, shard *frost.Shard, preSignatureBatch PreSignatureBatch, firstUnusedPreSignatureIndex int, privateNoncePairs []*PrivateNoncePair, presentParties, signatureAggregators ds.HashSet[types.IdentityKey], protocol types.ThresholdSignatureProtocol, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if err := preSignatureBatch.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "presignature batch")
	}
	if firstUnusedPreSignatureIndex < 0 || firstUnusedPreSignatureIndex >= len(preSignatureBatch) {
		return errs.NewArgument("first unused pre signature index index is out of bound")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if signatureAggregators == nil {
		return errs.NewIsNil("signature aggregators")
	}
	if presentParties == nil {
		return errs.NewIsNil("present parties")
	}
	if !presentParties.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("present party set is not a subset of total")
	}
	if privateNoncePairs == nil {
		return errs.NewIsNil("private nonce pairs is nil")
	}
	if len(privateNoncePairs) != len(preSignatureBatch) {
		return errs.NewCount("number of provided private nonce pairs is not equal to total presignatures")
	}
	return nil
}
