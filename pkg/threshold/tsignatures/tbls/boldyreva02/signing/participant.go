package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Cosigner[K bls.KeySubGroup, S bls.SignatureSubGroup] struct {
	signer       *bls.Signer[K, S]
	cohortConfig *integration.CohortConfig

	myAuthKey              integration.AuthKey
	mySharingId            int
	myShard                *boldyreva02.Shard[K]
	identityKeyToSharingId map[types.IdentityHash]int
	scheme                 bls.RogueKeyPrevention

	sid        []byte
	transcript transcripts.Transcript
	round      int
}

func (p *Cosigner[K, S]) GetAuthKey() integration.AuthKey {
	return p.myAuthKey
}

func (p *Cosigner[K, S]) GetSharingId() int {
	return p.mySharingId
}

func (p *Cosigner[K, S]) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func (p *Cosigner[K, S]) IsSignatureAggregator() bool {
	for _, signatureAggregator := range p.cohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(p.myAuthKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewCosigner[K bls.KeySubGroup, S bls.SignatureSubGroup](sid []byte, authKey integration.AuthKey, scheme bls.RogueKeyPrevention, sessionParticipants *hashset.HashSet[integration.IdentityKey], myShard *boldyreva02.Shard[K], cohortConfig *integration.CohortConfig, transcript transcripts.Transcript) (*Cosigner[K, S], error) {
	if err := validateInputs[K, S](sid, authKey, sessionParticipants, myShard, cohortConfig); err != nil {
		return nil, errs.WrapInvalidArgument(err, "couldn't construct the cossigner")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_THRESHOLD_BLS_BOLDYREVA-", nil)
	}
	transcript.AppendMessages("threshold bls signing", sid)

	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(authKey, cohortConfig.Participants)

	signingKeyShareAsPrivateKey, err := bls.NewPrivateKey[K](myShard.SigningKeyShare.Share)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not consider my signing key share as a bls private key")
	}
	signer, err := bls.NewSigner[K, S](signingKeyShareAsPrivateKey, bls.POP)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't construct bls cosigner")
	}

	return &Cosigner[K, S]{
		signer:                 signer,
		cohortConfig:           cohortConfig,
		myAuthKey:              authKey,
		sid:                    sid,
		identityKeyToSharingId: identityKeyToSharingId,
		mySharingId:            mySharingId,
		myShard:                myShard,
		transcript:             transcript,
		scheme:                 scheme,
		round:                  1,
	}, nil
}

func validateInputs[K bls.KeySubGroup, S bls.SignatureSubGroup](sid []byte, myAuthKey integration.AuthKey, sessionParticipants *hashset.HashSet[integration.IdentityKey], shard *boldyreva02.Shard[K], cohortConfig *integration.CohortConfig) error {
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
		return errs.NewMembershipError("i'm not in cohort")
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
	if bls.SameSubGroup[K, S]() {
		return errs.NewInvalidType("key subgroup and signature subgroup can't be the same")
	}
	return nil
}
