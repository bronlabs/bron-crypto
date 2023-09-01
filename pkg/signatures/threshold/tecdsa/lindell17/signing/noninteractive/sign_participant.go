package noninteractive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

type Cosigner struct {
	lindell17.Participant

	myIdentityKey       integration.IdentityKey
	mySharingId         int
	myShard             *lindell17.Shard
	myPreSignatureBatch *lindell17.PreSignatureBatch

	theirIdentityKey integration.IdentityKey
	theirSharingId   int

	preSignatureIndex int
	cohortConfig      *integration.CohortConfig
	prng              io.Reader

	_ helper_types.Incomparable
}

func (p *Cosigner) GetIdentityKey() integration.IdentityKey {
	return p.myIdentityKey
}

func (p *Cosigner) GetSharingId() int {
	return p.mySharingId
}

func (p *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func (p *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range p.cohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(p.myIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewCosigner(cohortConfig *integration.CohortConfig, myIdentityKey integration.IdentityKey, myShard *lindell17.Shard, myPreSignatureBatch *lindell17.PreSignatureBatch, preSignatureIndex int, participantIdentity integration.IdentityKey, sid []byte, transcript transcripts.Transcript, prng io.Reader) (p *Cosigner, err error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if myShard == nil {
		return nil, errs.NewIsNil("shard is nil")
	}
	if err := myShard.SigningKeyShare.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if preSignatureIndex < 0 || preSignatureIndex >= len(myPreSignatureBatch.PreSignatures) {
		return nil, errs.NewInvalidArgument("first unused pre signature index index is out of bound")
	}

	_, keyToId, mySharingId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)
	theirSharingId := keyToId[participantIdentity.Hash()]

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sid)
	return &Cosigner{
		myIdentityKey:       myIdentityKey,
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
