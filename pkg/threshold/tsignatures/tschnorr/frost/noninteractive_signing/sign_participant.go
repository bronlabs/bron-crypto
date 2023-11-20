package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
)

var _ frost.Participant = (*Cosigner)(nil)

type Cosigner struct {
	prng io.Reader

	PreSignatures                *PreSignatureBatch
	FirstUnusedPreSignatureIndex int

	MyAuthKey   integration.AuthKey
	MySharingId int
	Shard       *frost.Shard

	CohortConfig           *integration.CohortConfig
	SessionParticipants    *hashset.HashSet[integration.IdentityKey]
	SharingIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToSharingId map[types.IdentityHash]int

	myPrivateNoncePairs []*PrivateNoncePair

	aggregationParameter *aggregation.SignatureAggregatorParameters

	_ types.Incomparable
}

func (nic *Cosigner) GetAuthKey() integration.AuthKey {
	return nic.MyAuthKey
}

func (nic *Cosigner) GetSharingId() int {
	return nic.MySharingId
}

func (nic *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return nic.CohortConfig
}

func (nic *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range nic.CohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(nic.MyAuthKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewNonInteractiveCosigner(
	authKey integration.AuthKey, shard *frost.Shard,
	preSignatureBatch *PreSignatureBatch, firstUnusedPreSignatureIndex int, privateNoncePairs []*PrivateNoncePair,
	presentParties *hashset.HashSet[integration.IdentityKey], cohortConfig *integration.CohortConfig, prng io.Reader,
) (*Cosigner, error) {
	err := validateParticipantInputs(authKey, shard, preSignatureBatch, firstUnusedPreSignatureIndex, privateNoncePairs, presentParties, cohortConfig, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}

	sharingIdToIdentityKey, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(authKey, cohortConfig.Participants)
	for i, privateNoncePair := range privateNoncePairs {
		preSignature := (*preSignatureBatch)[i]
		myAttestedCommitment := (*preSignature)[mySharingId-1]
		curve := myAttestedCommitment.D.Curve()
		if !curve.ScalarBaseMult(privateNoncePair.SmallD).Equal(myAttestedCommitment.D) {
			return nil, errs.NewFailed("my d nonce at index %d is not equal to the corresponding commitment", i)
		}
		if !curve.ScalarBaseMult(privateNoncePair.SmallE).Equal(myAttestedCommitment.E) {
			return nil, errs.NewFailed("my e nonce at index %d is not equal to the corresponding commitment", i)
		}
	}

	D_alpha := map[types.IdentityHash]curves.Point{}
	E_alpha := map[types.IdentityHash]curves.Point{}
	preSignature := (*preSignatureBatch)[firstUnusedPreSignatureIndex]
	for _, attestedCommitment := range *preSignature {
		_, found := presentParties.Get(attestedCommitment.Attestor)
		if !found {
			continue
		}
		D_alpha[attestedCommitment.Attestor.Hash()] = attestedCommitment.D
		E_alpha[attestedCommitment.Attestor.Hash()] = attestedCommitment.E
	}

	return &Cosigner{
		prng:                         prng,
		PreSignatures:                preSignatureBatch,
		FirstUnusedPreSignatureIndex: firstUnusedPreSignatureIndex,
		MyAuthKey:                    authKey,
		MySharingId:                  mySharingId,
		Shard:                        shard,
		CohortConfig:                 cohortConfig,
		SharingIdToIdentityKey:       sharingIdToIdentityKey,
		IdentityKeyToSharingId:       identityKeyToSharingId,
		SessionParticipants:          presentParties,
		myPrivateNoncePairs:          privateNoncePairs,
		aggregationParameter: &aggregation.SignatureAggregatorParameters{
			D_alpha: D_alpha,
			E_alpha: E_alpha,
		},
	}, nil
}

func validateParticipantInputs(identityKey integration.IdentityKey, shard *frost.Shard, preSignatureBatch *PreSignatureBatch, firstUnusedPreSignatureIndex int, privateNoncePairs []*PrivateNoncePair, presentParties *hashset.HashSet[integration.IdentityKey], cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if identityKey == nil {
		return errs.NewIsNil("identity key is nil")
	}
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if shard == nil {
		return errs.NewIsNil("shard is nil")
	}
	if err := shard.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if preSignatureBatch == nil {
		return errs.NewIsNil("pre signature batch is nil")
	}
	if err := preSignatureBatch.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "presignature batch is invalid")
	}
	if firstUnusedPreSignatureIndex < 0 || firstUnusedPreSignatureIndex >= len(*preSignatureBatch) {
		return errs.NewInvalidArgument("first unused pre signature index index is out of bound")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}

	for i, participant := range presentParties.Iter() {
		if participant == nil {
			return errs.NewIsNil("participant %x is nil", i)
		}
	}
	if presentParties.Len() <= 0 {
		return errs.NewInvalidArgument("no party is present")
	}
	for _, participant := range presentParties.Iter() {
		if !cohortConfig.IsInCohort(participant) {
			return errs.NewMissing("present party is not in cohort")
		}
	}

	if privateNoncePairs == nil {
		return errs.NewIsNil("private nonce pairs is nil")
	}
	if len(privateNoncePairs) != len(*preSignatureBatch) {
		return errs.NewIncorrectCount("number of provided private nonce pairs is not equal to total presignatures")
	}
	return nil
}
