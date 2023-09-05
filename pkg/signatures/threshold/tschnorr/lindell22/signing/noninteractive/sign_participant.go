package noninteractive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

type Cosigner struct {
	lindell22.Participant

	myIdentityKey  integration.IdentityKey
	mySharingId    int
	myShard        *lindell22.Shard
	myPreSignature *lindell22.PreSignature

	taproot                bool
	identityKeyToSharingId map[helper_types.IdentityHash]int
	sessionParticipants    *hashset.HashSet[integration.IdentityKey]
	cohortConfig           *integration.CohortConfig
	prng                   io.Reader

	_ helper_types.Incomparable
}

func (c *Cosigner) GetIdentityKey() integration.IdentityKey {
	return c.myIdentityKey
}

func (c *Cosigner) GetSharingId() int {
	return c.mySharingId
}

func (c *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return c.cohortConfig
}

func (c *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range c.cohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(c.myIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewCosigner(myIdentityKey integration.IdentityKey, myShard *lindell22.Shard, cohortConfig *integration.CohortConfig, sessionParticipants *hashset.HashSet[integration.IdentityKey], preSignatureIndex int, preSignatureBatch *lindell22.PreSignatureBatch, sid []byte, taproot bool, transcript transcripts.Transcript, prng io.Reader) (cosigner *Cosigner, err error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if err := myShard.Validate(cohortConfig); err != nil {
		return nil, errs.WrapInvalidArgument(err, "shard is invalid")
	}
	if err := validateCosignerInputs(myIdentityKey, myShard, cohortConfig); err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid arguments")
	}

	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sid)
	return &Cosigner{
		myIdentityKey:          myIdentityKey,
		mySharingId:            mySharingId,
		myShard:                myShard,
		myPreSignature:         preSignatureBatch.PreSignatures[preSignatureIndex],
		taproot:                taproot,
		identityKeyToSharingId: identityKeyToSharingId,
		sessionParticipants:    sessionParticipants,
		cohortConfig:           cohortConfig,
		prng:                   prng,
	}, nil
}

func validateCosignerInputs(identityKey integration.IdentityKey, shard *lindell22.Shard, cohortConfig *integration.CohortConfig) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Participants.Len() != cohortConfig.Protocol.TotalParties {
		return errs.NewIncorrectCount("invalid number of participants")
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
