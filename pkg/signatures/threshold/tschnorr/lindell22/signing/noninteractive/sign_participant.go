package noninteractive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
)

type Cosigner struct {
	lindell22.Participant

	myIdentityKey  integration.IdentityKey
	myShamirId     int
	myShard        *lindell22.Shard
	myPreSignature *lindell22.PreSignature

	identityKeyToShamirId map[integration.IdentityKey]int
	sessionParticipants   []integration.IdentityKey
	cohortConfig          *integration.CohortConfig
	prng                  io.Reader
}

func (c *Cosigner) GetIdentityKey() integration.IdentityKey {
	return c.myIdentityKey
}

func (c *Cosigner) GetShamirId() int {
	return c.myShamirId
}

func (c *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return c.cohortConfig
}

func (c *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range c.cohortConfig.SignatureAggregators {
		if signatureAggregator.PublicKey().Equal(c.myIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewCosigner(myIdentityKey integration.IdentityKey, myShard *lindell22.Shard, cohortConfig *integration.CohortConfig, sessionParticipants []integration.IdentityKey, preSignatureIndex int, preSignatureBatch *lindell22.PreSignatureBatch, prng io.Reader) (cosigner *Cosigner, err error) {
	if err := validateCosignerInputs(myIdentityKey, myShard, cohortConfig); err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid arguments")
	}

	_, identityKeyToShamirId, myShamirId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)
	return &Cosigner{
		myIdentityKey:         myIdentityKey,
		myShamirId:            myShamirId,
		myShard:               myShard,
		myPreSignature:        preSignatureBatch.PreSignatures[preSignatureIndex],
		identityKeyToShamirId: identityKeyToShamirId,
		sessionParticipants:   sessionParticipants,
		cohortConfig:          cohortConfig,
		prng:                  prng,
	}, nil
}

func validateCosignerInputs(identityKey integration.IdentityKey, shard *lindell22.Shard, cohortConfig *integration.CohortConfig) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if len(cohortConfig.Participants) != cohortConfig.TotalParties {
		return errs.NewIncorrectCount("invalid number of participants")
	}
	if cohortConfig.PreSignatureComposer != nil {
		return errs.NewVerificationFailed("can't set presignature composer if cosigner is interactive")
	}
	if shard == nil || shard.SigningKeyShare == nil {
		return errs.NewVerificationFailed("shard is nil")
	}
	if err := shard.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if identityKey == nil || !cohortConfig.IsInCohort(identityKey) {
		return errs.NewInvalidArgument("identityKey not in cohort")
	}

	return nil
}
