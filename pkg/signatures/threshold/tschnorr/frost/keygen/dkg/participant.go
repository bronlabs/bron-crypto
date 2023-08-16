package dkg

import (
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/dkg/pedersen"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
)

type Participant struct {
	pedersenParty *pedersen.Participant

	_ helper_types.Incomparable
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.pedersenParty.GetIdentityKey()
}

func (p *Participant) GetSharingId() int {
	return p.pedersenParty.GetSharingId()
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
