package dkg

import (
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
)

type Participant struct {
	pedersenParty *pedersen.Participant

	_ types.Incomparable
}

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.pedersenParty.GetAuthKey()
}

func (p *Participant) GetSharingId() int {
	return p.pedersenParty.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.pedersenParty.GetCohortConfig()
}

func NewParticipant(uniqueSessionId []byte, authKey integration.AuthKey, cohortConfig *integration.CohortConfig, prng io.Reader) (*Participant, error) {
	err := validateInputs(cohortConfig, authKey, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}
	party, err := pedersen.NewParticipant(uniqueSessionId, authKey, cohortConfig, nil, randomisedFischlin.Name, prng)
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
