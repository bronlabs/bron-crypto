package noninteractive

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
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if !cohortConfig.IsInCohort(identityKey) {
		return nil, errs.NewMissing("identity key is not in cohort")
	}
	if tau <= 0 {
		return nil, errs.NewInvalidArgument("tau is nonpositive")
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
