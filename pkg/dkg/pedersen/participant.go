package pedersen

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/feldman"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	MyIdentityKey      integration.IdentityKey
	MyShamirId         int
	UniqueSessionId    []byte
	myPartialPublicKey curves.Point
	secretKeyShare     curves.Scalar

	CohortConfig          *integration.CohortConfig
	shamirIdToIdentityKey map[int]integration.IdentityKey

	round int
	state *State
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) GetShamirId() int {
	return p.MyShamirId
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

type State struct {
	r_i         curves.Scalar
	shareVector []*feldman.Share
	commitments []curves.Point
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader) (*Participant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	result := &Participant{
		MyIdentityKey:   identityKey,
		UniqueSessionId: uniqueSessionId,
		state:           &State{},
		prng:            prng,
		CohortConfig:    cohortConfig,
	}
	result.shamirIdToIdentityKey, _, result.MyShamirId = integration.DeriveSharingIds(identityKey, result.CohortConfig.Participants)
	result.round = 1
	return result, nil
}
