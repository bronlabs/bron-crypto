package tecdsa

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/agreeonrandom"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	dkls23 "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/keygen/dkg"
	lindell17 "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/keygen/dkg"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

const DKGLabel = "COPPER_KNOX_DKG_TECDSA-"

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	MyIdentityKey integration.IdentityKey
	CohortConfig  *integration.CohortConfig

	UniqueSessionId []byte
	SIDParty        *agreeonrandom.Participant
	Main            *dkls23.Participant
	Backup          *lindell17.Participant
	Shard           *Shard

	transcript transcripts.Transcript
	prng       io.Reader
	round      int

	_ helper_types.Incomparable
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) GetSharingId() int {
	return p.Main.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

func NewParticipant(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader) (*Participant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if cohortConfig.CipherSuite.Curve.Name() != k256.Name && cohortConfig.CipherSuite.Curve.Name() != p256.Name {
		return nil, errs.NewInvalidCurve("only K256 and P256 curves are supported")
	}
	transcript := hagrid.NewTranscript(DKGLabel)
	sidParty, err := agreeonrandom.NewParticipant(cohortConfig.CipherSuite.Curve, identityKey, cohortConfig.Participants, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct frost dkg participant out of pedersen dkg participant")
	}
	if prng == nil {
		prng = crand.Reader
	}
	return &Participant{
		MyIdentityKey: identityKey,
		CohortConfig:  cohortConfig,
		SIDParty:      sidParty,
		Shard:         &Shard{},
		transcript:    transcript,
		prng:          prng,
		round:         1,
	}, nil
}
