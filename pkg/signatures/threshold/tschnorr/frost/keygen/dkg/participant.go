package dkg

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/dkg/pedersen"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
)

type Participant struct {
	pedersenParty *pedersen.Participant
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.pedersenParty.GetIdentityKey()
}

func (p *Participant) GetShamirId() int {
	return p.pedersenParty.GetShamirId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.pedersenParty.GetCohortConfig()
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader) (*Participant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	party, err := pedersen.NewParticipant(uniqueSessionId, identityKey, cohortConfig, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct frost dkg participant out of pedersen dkg participant")
	}
	return &Participant{
		pedersenParty: party,
	}, nil
}
