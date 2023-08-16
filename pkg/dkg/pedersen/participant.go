package pedersen

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/sharing/feldman"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	MyIdentityKey   integration.IdentityKey
	MySharingId     int
	UniqueSessionId []byte

	CohortConfig           *integration.CohortConfig
	sharingIdToIdentityKey map[int]integration.IdentityKey

	round int
	state *State

	_ helper_types.Incomparable
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) GetSharingId() int {
	return p.MySharingId
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

type State struct {
	shareVector []*feldman.Share
	commitments []curves.Point

	_ helper_types.Incomparable
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
	result.sharingIdToIdentityKey, _, result.MySharingId = integration.DeriveSharingIds(identityKey, result.CohortConfig.Participants)
	result.round = 1
	return result, nil
}
