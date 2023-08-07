package noninteractive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
)

type Cosigner struct {
	lindell17.Participant

	myIdentityKey       integration.IdentityKey
	myShamirId          int
	myShard             *lindell17.Shard
	myPreSignatureBatch *lindell17.PreSignatureBatch

	theirIdentityKey integration.IdentityKey
	theirShamirId    int

	preSignatureIndex int
	cohortConfig      *integration.CohortConfig
	prng              io.Reader
}

func (p *Cosigner) GetIdentityKey() integration.IdentityKey {
	return p.myIdentityKey
}

func (p *Cosigner) GetShamirId() int {
	return p.myShamirId
}

func (p *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func (p *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range p.cohortConfig.SignatureAggregators {
		if signatureAggregator.PublicKey().Equal(p.myIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewCosigner(cohortConfig *integration.CohortConfig, myIdentityKey integration.IdentityKey, myShard *lindell17.Shard, myPreSignatureBatch *lindell17.PreSignatureBatch, preSignatureIndex int, participantIdentity integration.IdentityKey, prng io.Reader) (p *Cosigner, err error) {
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

	_, keyToId, myShamirId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)
	theirShamirId := keyToId[participantIdentity]

	return &Cosigner{
		myIdentityKey:       myIdentityKey,
		myShamirId:          myShamirId,
		myShard:             myShard,
		myPreSignatureBatch: myPreSignatureBatch,
		theirIdentityKey:    participantIdentity,
		theirShamirId:       theirShamirId,
		preSignatureIndex:   preSignatureIndex,
		cohortConfig:        cohortConfig,
		prng:                prng,
	}, nil
}
