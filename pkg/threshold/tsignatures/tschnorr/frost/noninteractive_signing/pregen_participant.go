package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

var _ integration.Participant = (*PreGenParticipant)(nil)

type PreGenParticipant struct {
	prng io.Reader

	Tau          int
	MyAuthKey    integration.AuthKey
	CohortConfig *integration.CohortConfig
	round        int
	state        *preGenState

	_ types.Incomparable
}

type preGenState struct {
	ds          []curves.Scalar
	es          []curves.Scalar
	Commitments []*AttestedCommitmentToNoncePair

	_ types.Incomparable
}

func NewPreGenParticipant(authKey integration.AuthKey, cohortConfig *integration.CohortConfig, tau int, prng io.Reader) (*PreGenParticipant, error) {
	err := validateInputs(authKey, cohortConfig, tau, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}

	return &PreGenParticipant{
		prng:         prng,
		Tau:          tau,
		MyAuthKey:    authKey,
		CohortConfig: cohortConfig,
		round:        1,
		state:        &preGenState{},
	}, nil
}

func validateInputs(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, tau int, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if identityKey == nil {
		return errs.NewMissing("identity key is nil")
	}
	if !cohortConfig.IsInCohort(identityKey) {
		return errs.NewMissing("identity key is not in cohort")
	}
	if tau <= 0 {
		return errs.NewInvalidArgument("tau is nonpositive")
	}
	if prng == nil {
		return errs.NewMissing("PRNG is nil")
	}
	return nil
}

func (p *PreGenParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

func (p *PreGenParticipant) GetAuthKey() integration.AuthKey {
	return p.MyAuthKey
}

// TODO: implement SharingId for FROSTs
func (*PreGenParticipant) GetSharingId() int {
	return -1
}
