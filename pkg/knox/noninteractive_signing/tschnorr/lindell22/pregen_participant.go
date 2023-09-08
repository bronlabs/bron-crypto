package lindell22

import (
	"io"
	"strconv"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/commitments"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/copperexchange/krypton/pkg/transcripts"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
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
	bigR                []curves.Point
	bigRWitness         []commitments.Witness
	theirBigRCommitment []map[types.IdentityHash]commitments.Commitment

	_ types.Incomparable
}

type PreGenParticipant struct {
	lindell22.Participant

	myIdentityKey integration.IdentityKey
	mySharingId   int

	cohortConfig *integration.CohortConfig
	tau          int
	sid          []byte
	round        int
	prng         io.Reader
	transcript   transcripts.Transcript

	state *state

	_ types.Incomparable
}

func (p *PreGenParticipant) GetIdentityKey() integration.IdentityKey {
	return p.myIdentityKey
}

func (p *PreGenParticipant) GetSharingId() int {
	return p.mySharingId
}

func (p *PreGenParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func (p *PreGenParticipant) IsSignatureAggregator() bool {
	for _, signatureAggregator := range p.cohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(p.myIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewPreGenParticipant(tau int, myIdentityKey integration.IdentityKey, sid []byte, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader) (participant *PreGenParticipant, err error) {
	if err := validatePreGenInputs(tau, myIdentityKey, sid, cohortConfig); err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid argument")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sid)
	transcript.AppendMessages(transcriptTauLabel, []byte(strconv.Itoa(tau)))

	pid := myIdentityKey.PublicKey().ToAffineCompressed()
	bigS := signing.BigS(cohortConfig.Participants)
	_, _, mySharingId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)

	return &PreGenParticipant{
		myIdentityKey: myIdentityKey,
		mySharingId:   mySharingId,
		cohortConfig:  cohortConfig,
		tau:           tau,
		sid:           sid,
		transcript:    transcript,
		round:         1,
		prng:          prng,
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
