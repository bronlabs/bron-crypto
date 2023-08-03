package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript/merlin"
	"io"
)

type preGenParticipantState struct {
	k           []curves.Scalar
	bigR        []curves.Point
	bigRWitness []commitments.Witness

	theirBigRCommitments []map[integration.IdentityKey]commitments.Commitment
	theirBigR            []map[integration.IdentityKey]curves.Point
}

type PreGenParticipant struct {
	lindell17.Participant

	myIdentityKey integration.IdentityKey
	myShamirId    int
	tau           int
	cohortConfig  *integration.CohortConfig
	sid           []byte
	transcript    transcript.Transcript
	round         int
	prng          io.Reader

	state *preGenParticipantState
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

const (
	transcriptAppLabel       = "Lindell2017_PreGen"
	transcriptSessionIdLabel = "Lindell2017_PreGen_SessionId"
)

func NewPreGenParticipant(sid []byte, transcript transcript.Transcript, myIdentityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, tau int, prng io.Reader) (participant *PreGenParticipant, err error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if !cohortConfig.IsInCohort(myIdentityKey) {
		return nil, errs.NewMissing("identity key is not in cohort")
	}
	if tau <= 0 {
		return nil, errs.NewInvalidArgument("tau is non-positive")
	}
	if sid == nil || len(sid) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sid)
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptAppLabel)
	}
	err = transcript.AppendMessage([]byte(transcriptSessionIdLabel), sid)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot write to transcript")
	}

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
