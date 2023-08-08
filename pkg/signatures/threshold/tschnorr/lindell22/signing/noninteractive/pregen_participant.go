package noninteractive

import (
	"io"
	"strconv"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
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
	theirBigRCommitment []map[integration.IdentityKey]commitments.Commitment
}

type PreGenParticipant struct {
	lindell22.Participant

	myIdentityKey integration.IdentityKey
	myShamirId    int

	cohortConfig *integration.CohortConfig
	tau          int
	sid          []byte
	round        int
	prng         io.Reader
	transcript   transcripts.Transcript

	state *state
}

func (p *PreGenParticipant) GetIdentityKey() integration.IdentityKey {
	return p.myIdentityKey
}

func (p *PreGenParticipant) GetShamirId() int {
	return p.myShamirId
}

func (p *PreGenParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func (p *PreGenParticipant) IsSignatureAggregator() bool {
	for _, signatureAggregator := range p.cohortConfig.SignatureAggregators {
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
		transcript = merlin.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessage(transcriptSessionIdLabel, sid)
	transcript.AppendMessage(transcriptTauLabel, []byte(strconv.Itoa(tau)))

	pid := myIdentityKey.PublicKey().ToAffineCompressed()
	bigS := signing.BigS(cohortConfig.Participants)
	_, _, myShamirId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)

	return &PreGenParticipant{
		myIdentityKey: myIdentityKey,
		myShamirId:    myShamirId,
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
	if len(sid) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if len(cohortConfig.Participants) != cohortConfig.TotalParties {
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
