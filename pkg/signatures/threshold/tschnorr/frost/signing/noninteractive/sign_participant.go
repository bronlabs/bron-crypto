package noninteractive

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/signing/aggregation"
)

var _ frost.Participant = (*NonInteractiveCosigner)(nil)

type NonInteractiveCosigner struct {
	prng io.Reader

	PreSignatures                *PreSignatureBatch
	FirstUnusedPreSignatureIndex int

	MyIdentityKey integration.IdentityKey
	MyShamirId    int
	Shard         *frost.Shard

	CohortConfig          *integration.CohortConfig
	SessionParticipants   []integration.IdentityKey
	ShamirIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToShamirId map[integration.IdentityKey]int

	myPrivateNoncePairs []*PrivateNoncePair

	aggregationParameter *aggregation.SignatureAggregatorParameters
}

func (nic *NonInteractiveCosigner) GetIdentityKey() integration.IdentityKey {
	return nic.MyIdentityKey
}

func (nic *NonInteractiveCosigner) GetShamirId() int {
	return nic.MyShamirId
}

func (nic *NonInteractiveCosigner) GetCohortConfig() *integration.CohortConfig {
	return nic.CohortConfig
}

func (nic *NonInteractiveCosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range nic.CohortConfig.SignatureAggregators {
		if signatureAggregator.PublicKey().Equal(nic.MyIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewNonInteractiveCosigner(
	identityKey integration.IdentityKey, shard *frost.Shard,
	preSignatureBatch *PreSignatureBatch, firstUnusedPreSignatureIndex int, privateNoncePairs []*PrivateNoncePair,
	presentParties []integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader,
) (*NonInteractiveCosigner, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if shard == nil {
		return nil, errs.NewIsNil("shard is nil")
	}
	if err := shard.SigningKeyShare.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if err := preSignatureBatch.Validate(cohortConfig); err != nil {
		return nil, errs.WrapVerificationFailed(err, "presignature batch is invalid")
	}
	if firstUnusedPreSignatureIndex < 0 || firstUnusedPreSignatureIndex >= len(*preSignatureBatch) {
		return nil, errs.NewInvalidArgument("first unused pre signature index index is out of bound")
	}

	shamirIdToIdentityKey, identityKeyToShamirId, myShamirId := integration.DeriveSharingIds(identityKey, cohortConfig.Participants)

	presentPartiesHashSet := map[integration.IdentityKey]bool{}
	for _, participant := range presentParties {
		if presentPartiesHashSet[participant] {
			return nil, errs.NewDuplicate("found duplicate present party")
		}
		presentPartiesHashSet[participant] = true

		if !cohortConfig.IsInCohort(participant) {
			return nil, errs.NewMissing("present party is not in cohort")
		}
	}
	if len(presentPartiesHashSet) <= 0 {
		return nil, errs.NewInvalidArgument("no party is present")
	}

	if privateNoncePairs == nil {
		return nil, errs.NewIsNil("private nonce pairs is nil")
	}
	if len(privateNoncePairs) != len(*preSignatureBatch) {
		return nil, errs.NewIncorrectCount("number of provided private nonce pairs is not equal to total presignatures")
	}
	for i, privateNoncePair := range privateNoncePairs {
		preSignature := (*preSignatureBatch)[i]
		myAttestedCommitment := (*preSignature)[myShamirId-1]
		curve, err := curves.GetCurveByName(myAttestedCommitment.D.CurveName())
		if err != nil {
			return nil, errs.WrapInvalidCurve(err, "no such curve")
		}
		if !curve.ScalarBaseMult(privateNoncePair.SmallD).Equal(myAttestedCommitment.D) {
			return nil, errs.NewFailed("my d nonce at index %d is not equal to the corresponding commitment", i)
		}
		if !curve.ScalarBaseMult(privateNoncePair.SmallE).Equal(myAttestedCommitment.E) {
			return nil, errs.NewFailed("my e nonce at index %d is not equal to the corresponding commitment", i)
		}
	}

	D_alpha := map[integration.IdentityKey]curves.Point{}
	E_alpha := map[integration.IdentityKey]curves.Point{}
	preSignature := (*preSignatureBatch)[firstUnusedPreSignatureIndex]
	for _, attestedCommitment := range *preSignature {
		if !presentPartiesHashSet[attestedCommitment.Attestor] {
			continue
		}
		D_alpha[attestedCommitment.Attestor] = attestedCommitment.D
		E_alpha[attestedCommitment.Attestor] = attestedCommitment.E
	}

	return &NonInteractiveCosigner{
		prng:                         prng,
		PreSignatures:                preSignatureBatch,
		FirstUnusedPreSignatureIndex: firstUnusedPreSignatureIndex,
		MyIdentityKey:                identityKey,
		MyShamirId:                   myShamirId,
		Shard:                        shard,
		CohortConfig:                 cohortConfig,
		ShamirIdToIdentityKey:        shamirIdToIdentityKey,
		IdentityKeyToShamirId:        identityKeyToShamirId,
		SessionParticipants:          presentParties,
		myPrivateNoncePairs:          privateNoncePairs,
		aggregationParameter: &aggregation.SignatureAggregatorParameters{
			D_alpha: D_alpha,
			E_alpha: E_alpha,
		},
	}, nil
}
