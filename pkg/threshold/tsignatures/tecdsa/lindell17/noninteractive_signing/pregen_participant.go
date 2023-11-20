package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type preGenParticipantState struct {
	k           []curves.Scalar
	bigR        []curves.Point
	bigRWitness []commitments.Witness

	theirBigRCommitments []map[types.IdentityHash]commitments.Commitment

	_ types.Incomparable
}

type PreGenParticipant struct {
	lindell17.Participant

	myAuthKey    integration.AuthKey
	mySharingId  int
	tau          int
	cohortConfig *integration.CohortConfig
	sid          []byte
	transcript   transcripts.Transcript
	round        int
	prng         io.Reader

	state *preGenParticipantState

	_ types.Incomparable
}

func (p *PreGenParticipant) GetAuthKey() integration.AuthKey {
	return p.myAuthKey
}

func (p *PreGenParticipant) GetSharingId() int {
	return p.mySharingId
}

func (p *PreGenParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func (p *PreGenParticipant) IsSignatureAggregator() bool {
	for _, signatureAggregator := range p.cohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(p.myAuthKey.PublicKey()) {
			return true
		}
	}
	return false
}

const (
	transcriptAppLabel       = "Lindell2017_PreGen"
	transcriptSessionIdLabel = "Lindell2017_PreGen_SessionId"
)

func NewPreGenParticipant(sid []byte, transcript transcripts.Transcript, myAuthKey integration.AuthKey, cohortConfig *integration.CohortConfig, tau int, prng io.Reader) (participant *PreGenParticipant, err error) {
	err = validateInputs(sid, myAuthKey, cohortConfig, tau, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sid)

	return &PreGenParticipant{
		myAuthKey:    myAuthKey,
		cohortConfig: cohortConfig,
		tau:          tau,
		prng:         prng,
		sid:          sid,
		transcript:   transcript,
		round:        1,
		state:        &preGenParticipantState{},
	}, nil
}

func validateInputs(sid []byte, myAuthKey integration.AuthKey, cohortConfig *integration.CohortConfig, tau int, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if myAuthKey == nil {
		return errs.NewMissing("identity key is nil")
	}
	if prng == nil {
		return errs.NewMissing("prng is nil")
	}
	if !cohortConfig.IsInCohort(myAuthKey) {
		return errs.NewMissing("identity key is not in cohort")
	}
	if tau <= 0 {
		return errs.NewInvalidArgument("tau is non-positive")
	}
	if len(sid) == 0 {
		return errs.NewInvalidArgument("invalid session id: %s", sid)
	}
	return nil
}
