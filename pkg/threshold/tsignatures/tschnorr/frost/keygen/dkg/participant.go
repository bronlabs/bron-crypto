package dkg

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"

	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/threshold/dkg/pedersen"

	"github.com/copperexchange/knox-primitives/pkg/base/integration"
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
	err := validateInputs(cohortConfig, identityKey, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}
	party, err := pedersen.NewParticipant(uniqueSessionId, identityKey, cohortConfig, nil, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct frost dkg participant out of pedersen dkg participant")
	}
	return &Participant{
		pedersenParty: party,
	}, nil
}

func validateInputs(cohortConfig *integration.CohortConfig, identityKey integration.IdentityKey, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if identityKey == nil {
		return errs.NewInvalidArgument("identity key is nil")
	}
	if prng == nil {
		return errs.NewInvalidArgument("prng is nil")
	}
	return nil
}
