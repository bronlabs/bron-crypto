package prss

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

type SampleParticipant struct {
	cohortConfig *integration.CohortConfig
	myIdentity   integration.AuthKey
	mySharingId  int
	idToKey      map[int]integration.IdentityKey
	keyToId      map[types.IdentityHash]int
	subSets      []*SubSet
	t            int
	prng         io.Reader
	ra           map[int]curves.Scalar
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

func NewSampleParticipant(myAuthKey integration.AuthKey, cohortConfig *integration.CohortConfig, ra map[int]curves.Scalar, prng io.Reader) (*SampleParticipant, error) {
	idToKey, keyToId, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)
	t := cohortConfig.Protocol.Threshold - 1
	subSets := NewSubSets(cohortConfig.Participants, cohortConfig.Protocol.TotalParties-t)

	participant := &SampleParticipant{
		cohortConfig: cohortConfig,
		myIdentity:   myAuthKey,
		mySharingId:  mySharingId,
		idToKey:      idToKey,
		keyToId:      keyToId,
		subSets:      subSets,
		t:            t,
		prng:         prng,
		ra:           ra,
	}

	return participant, nil
}
