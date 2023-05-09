package pregen

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/noninteractive"
	"github.com/pkg/errors"
)

type PreGenParticipant struct {
	reader io.Reader

	Tau           int
	MyIdentityKey integration.IdentityKey
	CohortConfig  *integration.CohortConfig
	round         int
	state         *preGenState
}

type preGenState struct {
	ds          []curves.Scalar
	es          []curves.Scalar
	Commitments []*noninteractive.AttestedCommitmentToNoncePair
}

func NewPreGenParticipant(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, tau int, reader io.Reader) (*PreGenParticipant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrap(err, "cohort config is invalid")
	}
	if !cohortConfig.IsInCohort(identityKey) {
		return nil, errors.New("identity key is not in cohort")
	}
	if tau <= 0 {
		return nil, errors.New("tau is nonpositive")
	}
	integration.SortIdentityKeysInPlace(cohortConfig.Participants)
	return &PreGenParticipant{
		reader:        reader,
		Tau:           tau,
		MyIdentityKey: identityKey,
		CohortConfig:  cohortConfig,
		round:         1,
		state:         &preGenState{},
	}, nil
}
