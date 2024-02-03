package prss

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

type SetupParticipant struct {
	cohortConfig *integration.CohortConfig
	myIdentity   integration.AuthKey
	mySharingId  int
	subSets      []*SubSet
	prng         io.Reader
	state        *state
}

func (p *SetupParticipant) GetAuthKey() integration.AuthKey {
	return p.myIdentity
}

func (p *SetupParticipant) GetSharingId() int {
	return p.mySharingId
}

func (p *SetupParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

var _ integration.Participant = (*SetupParticipant)(nil)

type state struct {
	ra map[int]curves.Scalar
}

func NewSetupParticipant(myIdentity integration.AuthKey, cohortConfig *integration.CohortConfig, prng io.Reader) (*SetupParticipant, error) {
	_, _, mySharingId := integration.DeriveSharingIds(myIdentity, cohortConfig.Participants)
	t := cohortConfig.Protocol.Threshold - 1
	subSets := NewSubSets(cohortConfig.Participants, cohortConfig.Protocol.TotalParties-t)

	participant := &SetupParticipant{
		myIdentity:   myIdentity,
		mySharingId:  mySharingId,
		cohortConfig: cohortConfig,
		subSets:      subSets,
		prng:         prng,
		state:        &state{},
	}

	return participant, nil
}
