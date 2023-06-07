package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/pkg/errors"
)

var _ frost.Participant = (*NonInteractiveCosigner)(nil)

type NonInteractiveCosigner struct {
	prng io.Reader

	PreSignatures                *PreSignatureBatch
	FirstUnusedPreSignatureIndex int

	MyIdentityKey   integration.IdentityKey
	MyShamirId      int
	SigningKeyShare *frost.SigningKeyShare

	CohortConfig          *integration.CohortConfig
	PublicKeyShares       *frost.PublicKeyShares
	SessionParticipants   []integration.IdentityKey
	ShamirIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToShamirId map[integration.IdentityKey]int

	// The following correspond to the right presignature index
	D_alpha             map[integration.IdentityKey]curves.Point
	E_alpha             map[integration.IdentityKey]curves.Point
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
	identityKey integration.IdentityKey, signingKeyShare *frost.SigningKeyShare, publicKeyShare *frost.PublicKeyShares,
	preSignatureBatch *PreSignatureBatch, firstUnusedPreSignatureIndex int, privateNoncePairs []*PrivateNoncePair,
	presentParties []integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader,
) (*NonInteractiveCosigner, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrapf(err, "%s cohort config is invalid", errs.VerificationFailed)
	}
	if err := signingKeyShare.Validate(); err != nil {
		return nil, errors.Wrapf(err, "%s could not validate signing key share", errs.VerificationFailed)
	}
	if err := preSignatureBatch.Validate(cohortConfig); err != nil {
		return nil, errors.Wrapf(err, "%s presignature batch is invalid", errs.VerificationFailed)
	}
	if firstUnusedPreSignatureIndex < 0 || firstUnusedPreSignatureIndex >= len(*preSignatureBatch) {
		return nil, errors.Errorf("%s first unused pre signature index index is out of bound", errs.InvalidArgument)
	}

	shamirIdToIdentityKey, identityKeyToShamirId, myShamirId := frost.DeriveShamirIds(identityKey, cohortConfig.Participants)

	presentPartiesHashSet := map[integration.IdentityKey]bool{}
	for _, participant := range presentParties {
		if presentPartiesHashSet[participant] {
			return nil, errors.Errorf("%s found duplicate present party", errs.Duplicate)
		}
		presentPartiesHashSet[participant] = true

		if !cohortConfig.IsInCohort(participant) {
			return nil, errors.Errorf("%s present party is not in cohort", errs.Missing)
		}
	}
	if len(presentPartiesHashSet) <= 0 {
		return nil, errors.Errorf("%s no party is present", errs.InvalidArgument)
	}

	if privateNoncePairs == nil {
		return nil, errors.Errorf("%s private nonce pairs is nil", errs.IsNil)
	}
	if len(privateNoncePairs) != len(*preSignatureBatch) {
		return nil, errors.Errorf("%s number of provided private nonce pairs is not equal to total presignatures", errs.IncorrectCount)
	}
	for i, privateNoncePair := range privateNoncePairs {
		preSignature := (*preSignatureBatch)[i]
		myAttestedCommitment := (*preSignature)[myShamirId-1]
		curve, err := curves.GetCurveByName(myAttestedCommitment.D.CurveName())
		if err != nil {
			return nil, errors.Wrapf(err, "%s no such curve", errs.InvalidCurve)
		}
		if !curve.ScalarBaseMult(privateNoncePair.SmallD).Equal(myAttestedCommitment.D) {
			return nil, errors.Errorf("%s my d nonce at index %d is not equal to the corresponding commitment", errs.Failed, i)
		}
		if !curve.ScalarBaseMult(privateNoncePair.SmallE).Equal(myAttestedCommitment.E) {
			return nil, errors.Errorf("%s my e nonce at index %d is not equal to the corresponding commitment", errs.Failed, i)
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
		SigningKeyShare:              signingKeyShare,
		CohortConfig:                 cohortConfig,
		PublicKeyShares:              publicKeyShare,
		ShamirIdToIdentityKey:        shamirIdToIdentityKey,
		IdentityKeyToShamirId:        identityKeyToShamirId,
		SessionParticipants:          presentParties,
		D_alpha:                      D_alpha,
		E_alpha:                      E_alpha,
		myPrivateNoncePairs:          privateNoncePairs,
		aggregationParameter:         &aggregation.SignatureAggregatorParameters{},
	}, nil
}
