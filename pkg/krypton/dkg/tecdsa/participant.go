package tecdsa

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	dkls23 "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/keygen/dkg"
	lindell17 "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const DKGLabel = "COPPER_KRYPTON_DKG_TECDSA-"

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	MyAuthKey    integration.AuthKey
	CohortConfig *integration.CohortConfig

	UniqueSessionId []byte
	Main            *dkls23.Participant
	Backup          *lindell17.Participant
	Shard           *Shard

	transcript transcripts.Transcript
	prng       io.Reader
	round      int

	_ types.Incomparable
}

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.MyAuthKey
}

func (p *Participant) GetSharingId() int {
	return p.Main.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

func NewParticipant(authKey integration.AuthKey, sid []byte, cohortConfig *integration.CohortConfig, prng io.Reader) (*Participant, error) {
	err := validateInputs(authKey, sid, cohortConfig, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}

	transcript := hagrid.NewTranscript(DKGLabel, nil)
	return &Participant{
		MyAuthKey:       authKey,
		CohortConfig:    cohortConfig,
		UniqueSessionId: sid,
		Shard:           &Shard{},
		transcript:      transcript,
		prng:            prng,
		round:           1,
	}, nil
}

func validateInputs(identityKey integration.IdentityKey, sid []byte, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if cohortConfig.CipherSuite.Curve.Name() != k256.Name && cohortConfig.CipherSuite.Curve.Name() != p256.Name {
		return errs.NewInvalidCurve("only K256 and P256 curves are supported")
	}
	if len(sid) == 0 {
		return errs.NewInvalidArgument("sid is empty")
	}
	if prng == nil {
		return errs.NewInvalidArgument("prng is nil")
	}
	if identityKey == nil {
		return errs.NewInvalidArgument("my identity key is nil")
	}
	if !cohortConfig.Participants.Contains(identityKey) {
		return errs.NewInvalidArgument("identity key is not in cohort config")
	}
	return nil
}
