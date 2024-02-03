package newprzs

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

type SampleParticipant struct {
	cohortConfig *integration.CohortConfig
	myIdentity   integration.AuthKey
	mySharingId  int
	idToKey      map[int]integration.IdentityKey
	keyToId      map[types.IdentityHash]int
	t            int
	prng         io.Reader
	sampler      *Sampler
}

func (p *SampleParticipant) GetAuthKey() integration.AuthKey {
	return p.myIdentity
}

func (p *SampleParticipant) GetSharingId() int {
	return p.mySharingId
}

func (p *SampleParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

var _ integration.Participant = (*SetupParticipant)(nil)

func NewSampleParticipant(myAuthKey integration.AuthKey, cohortConfig *integration.CohortConfig, seed *Seed, prng io.Reader) (*SampleParticipant, error) {
	idToKey, keyToId, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)
	t := cohortConfig.Protocol.Threshold - 1
	sampler := NewSampler(mySharingId-1, cohortConfig.Protocol.TotalParties, t, seed.Ra)

	participant := &SampleParticipant{
		cohortConfig: cohortConfig,
		myIdentity:   myAuthKey,
		mySharingId:  mySharingId,
		idToKey:      idToKey,
		keyToId:      keyToId,
		sampler:      sampler,
		t:            t,
		prng:         prng,
	}

	return participant, nil
}
