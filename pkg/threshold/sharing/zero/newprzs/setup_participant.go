package newprzs

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

type SetupParticipant struct {
	myAuthKey    integration.AuthKey
	mySharingId  int
	idToKey      map[int]integration.IdentityKey
	keyToId      map[types.IdentityHash]int
	cohortConfig *integration.CohortConfig
	prng         io.Reader
	state        *setupState
}

type setupState struct {
	ra map[int]curves.Scalar
}

func (p *SetupParticipant) GetAuthKey() integration.AuthKey {
	return p.myAuthKey
}

func (p *SetupParticipant) GetSharingId() int {
	return p.mySharingId
}

func (p *SetupParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

var _ integration.Participant = (*SetupParticipant)(nil)

func NewSetupParticipant(myAuthKey integration.AuthKey, cohortConfig *integration.CohortConfig, prng io.Reader) *SetupParticipant {
	idToKey, keyToId, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)

	setupParticipant := &SetupParticipant{
		myAuthKey:    myAuthKey,
		mySharingId:  mySharingId,
		idToKey:      idToKey,
		keyToId:      keyToId,
		cohortConfig: cohortConfig,
		prng:         prng,
		state:        &setupState{},
	}

	return setupParticipant
}
