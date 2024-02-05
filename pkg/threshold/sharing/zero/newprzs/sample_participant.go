package newprzs

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
)

type SampleParticipant struct {
	cohortConfig *integration.CohortConfig
	myIdentity   integration.AuthKey
	mySharingId  int
	idToKey      map[int]integration.IdentityKey
	keyToId      map[types.IdentityHash]int
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

func NewSampleParticipant(sessionId []byte, myAuthKey integration.AuthKey, cohortConfig *integration.CohortConfig, seed *Seed, seededPrngFactory csprng.CSPRNG) (*SampleParticipant, error) {
	idToKey, keyToId, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)
	t := cohortConfig.Protocol.Threshold - 2
	sampler, err := NewSampler(mySharingId-1, cohortConfig.Protocol.TotalParties, t, cohortConfig.CipherSuite.Curve.ScalarField(), sessionId, seed.Keys, seededPrngFactory)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create sampler")
	}

	participant := &SampleParticipant{
		cohortConfig: cohortConfig,
		myIdentity:   myAuthKey,
		mySharingId:  mySharingId,
		idToKey:      idToKey,
		keyToId:      keyToId,
		sampler:      sampler,
	}

	return participant, nil
}
