package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Cosigner struct {
	lindell17.Participant

	myAuthKey           integration.AuthKey
	mySharingId         int
	myShard             *lindell17.Shard
	myPreSignatureBatch *lindell17.PreSignatureBatch

	theirIdentityKey integration.IdentityKey
	theirSharingId   int

	preSignatureIndex int
	cohortConfig      *integration.CohortConfig
	prng              io.Reader

	_ types.Incomparable
}

func (p *Cosigner) GetAuthKey() integration.AuthKey {
	return p.myAuthKey
}

func (p *Cosigner) GetSharingId() int {
	return p.mySharingId
}

func (p *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func (p *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range p.cohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(p.myAuthKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewCosigner(cohortConfig *integration.CohortConfig, myAuthKey integration.AuthKey, myShard *lindell17.Shard, myPreSignatureBatch *lindell17.PreSignatureBatch, preSignatureIndex int, participantIdentity integration.IdentityKey, sid []byte, transcript transcripts.Transcript, prng io.Reader) (p *Cosigner, err error) {
	err = validateCosignerInputs(cohortConfig, myAuthKey, myShard, myPreSignatureBatch, preSignatureIndex, participantIdentity, sid, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}

	_, keyToId, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)
	theirSharingId := keyToId[participantIdentity.Hash()]

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sid)
	return &Cosigner{
		myAuthKey:           myAuthKey,
		mySharingId:         mySharingId,
		myShard:             myShard,
		myPreSignatureBatch: myPreSignatureBatch,
		theirIdentityKey:    participantIdentity,
		theirSharingId:      theirSharingId,
		preSignatureIndex:   preSignatureIndex,
		cohortConfig:        cohortConfig,
		prng:                prng,
	}, nil
}

func validateCosignerInputs(cohortConfig *integration.CohortConfig, myAuthKey integration.AuthKey, myShard *lindell17.Shard, myPreSignatureBatch *lindell17.PreSignatureBatch, preSignatureIndex int, participantIdentity integration.IdentityKey, sid []byte, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if myAuthKey == nil {
		return errs.NewIsNil("identity key is nil")
	}
	if participantIdentity == nil {
		return errs.NewIsNil("participant identity is nil")
	}
	if myShard == nil {
		return errs.NewIsNil("shard is nil")
	}
	if err := myShard.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if myPreSignatureBatch == nil {
		return errs.NewIsNil("pre signature batch is nil")
	}
	if len(sid) == 0 {
		return errs.NewIsNil("sid is empty")
	}
	if preSignatureIndex < 0 || preSignatureIndex >= len(myPreSignatureBatch.PreSignatures) {
		return errs.NewInvalidArgument("first unused pre signature index index is out of bound")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
