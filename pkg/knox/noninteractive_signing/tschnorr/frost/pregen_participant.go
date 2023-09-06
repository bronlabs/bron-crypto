package frost

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

type PreGenParticipant struct {
	prng io.Reader

	Tau           int
	MyIdentityKey integration.IdentityKey
	CohortConfig  *integration.CohortConfig
	round         int
	state         *preGenState

	_ helper_types.Incomparable
}

type preGenState struct {
	ds          []curves.Scalar
	es          []curves.Scalar
	Commitments []*AttestedCommitmentToNoncePair

	_ helper_types.Incomparable
}

func NewPreGenParticipant(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, tau int, prng io.Reader) (*PreGenParticipant, error) {
	err := validateInputs(identityKey, cohortConfig, tau, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}

	return &PreGenParticipant{
		prng:          prng,
		Tau:           tau,
		MyIdentityKey: identityKey,
		CohortConfig:  cohortConfig,
		round:         1,
		state:         &preGenState{},
	}, nil
}

func validateInputs(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, tau int, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
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
