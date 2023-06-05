package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/error_types"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/pkg/errors"
)

type PreGenParticipant struct {
	prng io.Reader

	Tau           int
	MyIdentityKey integration.IdentityKey
	CohortConfig  *integration.CohortConfig
	round         int
	state         *preGenState
}

type preGenState struct {
	ds          []curves.Scalar
	es          []curves.Scalar
	Commitments []*AttestedCommitmentToNoncePair
}

func NewPreGenParticipant(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, tau int, prng io.Reader) (*PreGenParticipant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrapf(err, "%s cohort config is invalid", error_types.EVerificationFailed)
	}
	if !cohortConfig.IsInCohort(identityKey) {
		return nil, errors.Errorf("%s identity key is not in cohort", error_types.EInvalidArgument)
	}
	if tau <= 0 {
		return nil, errors.Errorf("%s tau is nonpositive", error_types.EInvalidArgument)
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
