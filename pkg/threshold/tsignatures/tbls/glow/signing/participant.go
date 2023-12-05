package signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Cosigner struct {
	signer       *bls.Signer[bls.G1, bls.G2]
	cohortConfig *integration.CohortConfig

	myAuthKey              integration.AuthKey
	mySharingId            int
	myShard                *glow.Shard
	identityKeyToSharingId map[types.IdentityHash]int

	sid        []byte
	prng       io.Reader
	transcript transcripts.Transcript
	round      int
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

func NewCosigner(sid []byte, myAuthKey integration.AuthKey, sessionParticipants *hashset.HashSet[integration.IdentityKey], myShard *glow.Shard, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (*Cosigner, error) {
	if err := validateInputs(sid, myAuthKey, sessionParticipants, myShard, cohortConfig, prng); err != nil {
		return nil, errs.WrapInvalidArgument(err, "couldn't construct the cossigner")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(glow.TranscriptLabel, nil)
	}
	transcript.AppendMessages("threshold bls signing", sid)

	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)

	signingKeyShareAsPrivateKey, err := bls.NewPrivateKey[bls.G1](myShard.SigningKeyShare.Share)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consider my signing key share as a bls private key")
	}
	signer, err := bls.NewSigner[bls.G1, bls.G2](signingKeyShareAsPrivateKey, bls.Basic)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't construct bls cosigner")
	}

	return &Cosigner{
		signer:                 signer,
		cohortConfig:           cohortConfig,
		myAuthKey:              myAuthKey,
		sid:                    sid,
		identityKeyToSharingId: identityKeyToSharingId,
		mySharingId:            mySharingId,
		transcript:             transcript,
		myShard:                myShard,
		prng:                   prng,
		round:                  1,
	}, nil
}

func validateInputs(sid []byte, myAuthKey integration.AuthKey, sessionParticipants *hashset.HashSet[integration.IdentityKey], shard *glow.Shard, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if len(sid) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if cohortConfig.Protocol.Name != protocols.BLS {
		return errs.NewInvalidType("protocol %s is not BLS", cohortConfig.Protocol.Name)
	}
	if sessionParticipants.Len() > cohortConfig.Participants.Len() {
		return errs.NewIncorrectCount("too many present participants")
	}
	if sessionParticipants.Len() < cohortConfig.Protocol.Threshold {
		return errs.NewIncorrectCount("too few present participants")
	}
	if myAuthKey == nil {
		return errs.NewIsNil("my identity key is missing")
	}
	if !cohortConfig.IsInCohort(myAuthKey) {
		return errs.NewMembership("i'm not in cohort")
	}
	if shard == nil || shard.SigningKeyShare == nil {
		return errs.NewVerificationFailed("shard is nil")
	}
	if err := shard.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate shard")
	}
	if sessionParticipants == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if sessionParticipants.Difference(cohortConfig.Participants).Len() != 0 {
		return errs.NewIncorrectCount("sessionParticipants is not a subset of cohort config")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
