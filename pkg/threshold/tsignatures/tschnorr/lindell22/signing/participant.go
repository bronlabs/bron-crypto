package signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
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

	theirBigRCommitment map[types.IdentityHash]commitments.Commitment

	_ types.Incomparable
}

type Cosigner struct {
	lindell22.Participant
	myIdentityKey     integration.IdentityKey
	mySharingId       int
	mySigningKeyShare *tsignatures.SigningKeyShare

	taproot                bool
	cohortConfig           *integration.CohortConfig
	sessionParticipants    *hashset.HashSet[integration.IdentityKey]
	identityKeyToSharingId map[types.IdentityHash]int
	sid                    []byte
	round                  int
	transcript             transcripts.Transcript
	prng                   io.Reader

	state *state

	_ types.Incomparable
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

func NewCosigner(myIdentityKey integration.IdentityKey, sid []byte, sessionParticipants *hashset.HashSet[integration.IdentityKey], myShard *lindell22.Shard, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, taproot bool, prng io.Reader) (p *Cosigner, err error) {
	if err := validateInputs(sid, sessionParticipants, myShard, cohortConfig, prng); err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sid)

	pid := myIdentityKey.PublicKey().ToAffineCompressed()
	bigS := BigS(cohortConfig.Participants)
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
		taproot:                taproot,
		round:                  1,
		prng:                   prng,
		state: &state{
			pid:  pid,
			bigS: bigS,
		},
	}

	return cosigner, nil
}

func validateInputs(sid []byte, sessionParticipants *hashset.HashSet[integration.IdentityKey], shard *lindell22.Shard, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if len(sid) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if cohortConfig.Participants.Len() != cohortConfig.Protocol.TotalParties {
		return errs.NewIncorrectCount("invalid number of participants")
	}
	if shard == nil || shard.SigningKeyShare == nil {
		return errs.NewVerificationFailed("shard is nil")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if err := shard.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate shard")
	}
	if sessionParticipants == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if sessionParticipants.Len() != cohortConfig.Protocol.Threshold {
		return errs.NewIncorrectCount("invalid number of session participants")
	}
	for _, sessionParticipant := range sessionParticipants.Iter() {
		if !cohortConfig.IsInCohort(sessionParticipant) {
			return errs.NewInvalidArgument("invalid session participant")
		}
	}

	return nil
}
