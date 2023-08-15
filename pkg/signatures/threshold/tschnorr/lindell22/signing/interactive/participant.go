package interactive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

const (
	transcriptLabel          = "Lindell2022InteractiveSignCosignerStart"
	transcriptSessionIdLabel = "Lindell2022InteractiveSignSessionId"
)

type state struct {
	pid         []byte
	bigS        []byte
	k           curves.Scalar
	bigR        curves.Point
	bigRWitness commitments.Witness

	theirBigRCommitment map[integration.IdentityHash]commitments.Commitment
}

type Cosigner struct {
	lindell22.Participant
	myIdentityKey     integration.IdentityKey
	mySharingId       int
	mySigningKeyShare *threshold.SigningKeyShare

	cohortConfig           *integration.CohortConfig
	sessionParticipants    []integration.IdentityKey
	identityKeyToSharingId map[integration.IdentityHash]int
	sid                    []byte
	round                  int
	transcript             transcripts.Transcript
	prng                   io.Reader

	state *state
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
	for _, signatureAggregator := range p.cohortConfig.SignatureAggregators {
		if signatureAggregator.PublicKey().Equal(p.myIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewCosigner(myIdentityKey integration.IdentityKey, sid []byte, sessionParticipants []integration.IdentityKey, myShard *lindell22.Shard, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (p *Cosigner, err error) {
	if err := validateInputs(sid, sessionParticipants, myShard, cohortConfig); err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}

	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sid)

	pid := myIdentityKey.PublicKey().ToAffineCompressed()
	bigS := signing.BigS(cohortConfig.Participants)
	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)

	cosigner := &Cosigner{
		myIdentityKey:          myIdentityKey,
		mySharingId:            mySharingId,
		mySigningKeyShare:      myShard.SigningKeyShare,
		identityKeyToSharingId: identityKeyToSharingId,
		cohortConfig:           cohortConfig,
		sid:                    sid,
		transcript:             transcript,
		sessionParticipants:    sessionParticipants,
		round:                  1,
		prng:                   prng,
		state: &state{
			pid:  pid,
			bigS: bigS,
		},
	}

	return cosigner, nil
}

func validateInputs(sid []byte, sessionParticipants []integration.IdentityKey, shard *lindell22.Shard, cohortConfig *integration.CohortConfig) error {
	if len(sid) == 0 {
		return errs.NewIsNil("session id is empty")
	}
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
	if err := shard.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate shard")
	}
	if sessionParticipants == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if len(sessionParticipants) != cohortConfig.Threshold {
		return errs.NewIncorrectCount("invalid number of session participants")
	}
	for _, sessionParticipant := range sessionParticipants {
		if !cohortConfig.IsInCohort(sessionParticipant) {
			return errs.NewInvalidArgument("invalid session participant")
		}
	}

	return nil
}
