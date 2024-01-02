package noninteractive_signing

import (
	"io"
	"strconv"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/interactive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel          = "Lindell2022PreGenStart"
	transcriptSessionIdLabel = "Lindell2022PreGenSessionId"
	transcriptTauLabel       = "Lindell2022PreGenTau"
)

type state struct {
	pid                 []byte
	bigS                []byte
	k                   []curves.Scalar
	k2                  []curves.Scalar
	bigR                []curves.Point
	bigR2               []curves.Point
	bigRWitness         []commitments.Witness
	theirBigRCommitment []map[types.IdentityHash]commitments.Commitment
	zeroS               []map[types.IdentityHash]curves.Scalar

	_ types.Incomparable
}

type PreGenParticipant struct {
	lindell22.Participant

	myAuthKey   integration.AuthKey
	mySharingId int

	cohortConfig *integration.CohortConfig
	tau          int
	sid          []byte
	round        int
	prng         io.Reader
	transcript   transcripts.Transcript

	state *state

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

func NewPreGenParticipant(tau int, myAuthKey integration.AuthKey, sid []byte, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (participant *PreGenParticipant, err error) {
	if err := validatePreGenInputs(tau, myAuthKey, sid, cohortConfig); err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid argument")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sid)
	transcript.AppendMessages(transcriptTauLabel, []byte(strconv.Itoa(tau)))

	pid := myAuthKey.PublicKey().ToAffineCompressed()
	bigS := interactive_signing.BigS(cohortConfig.Participants)
	_, _, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)

	return &PreGenParticipant{
		myAuthKey:    myAuthKey,
		mySharingId:  mySharingId,
		cohortConfig: cohortConfig,
		tau:          tau,
		sid:          sid,
		transcript:   transcript,
		round:        1,
		prng:         prng,
		state: &state{
			pid:  pid,
			bigS: bigS,
		},
	}, nil
}

func validatePreGenInputs(tau int, identityKey integration.IdentityKey, sid []byte, cohortConfig *integration.CohortConfig) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if len(sid) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Participants.Len() != cohortConfig.Protocol.TotalParties {
		return errs.NewIncorrectCount("invalid number of participants")
	}
	if identityKey == nil || !cohortConfig.IsInCohort(identityKey) {
		return errs.NewInvalidArgument("identityKey not in cohort")
	}
	if tau <= 0 {
		return errs.NewInvalidArgument("tau is not positive")
	}

	return nil
}
