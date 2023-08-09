package noninteractive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

type preGenParticipantState struct {
	k           []curves.Scalar
	bigR        []curves.Point
	bigRWitness []commitments.Witness

	theirBigRCommitments []map[integration.IdentityKey]commitments.Commitment
}

type PreGenParticipant struct {
	lindell17.Participant

	myIdentityKey integration.IdentityKey
	mySharingId   int
	tau           int
	cohortConfig  *integration.CohortConfig
	sid           []byte
	transcript    transcripts.Transcript
	round         int
	prng          io.Reader

	state *preGenParticipantState
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
	for _, signatureAggregator := range p.cohortConfig.SignatureAggregators {
		if signatureAggregator.PublicKey().Equal(p.myIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

const (
	transcriptAppLabel       = "Lindell2017_PreGen"
	transcriptSessionIdLabel = "Lindell2017_PreGen_SessionId"
)

func NewPreGenParticipant(sid []byte, transcript transcripts.Transcript, myIdentityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, tau int, prng io.Reader) (participant *PreGenParticipant, err error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if !cohortConfig.IsInCohort(myIdentityKey) {
		return nil, errs.NewMissing("identity key is not in cohort")
	}
	if tau <= 0 {
		return nil, errs.NewInvalidArgument("tau is non-positive")
	}
	if len(sid) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sid)
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessage([]byte(transcriptSessionIdLabel), sid)

	return &PreGenParticipant{
		myIdentityKey: myIdentityKey,
		cohortConfig:  cohortConfig,
		tau:           tau,
		prng:          prng,
		sid:           sid,
		transcript:    transcript,
		round:         1,
		state:         &preGenParticipantState{},
	}, nil
}
