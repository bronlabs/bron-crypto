package newprzn

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"io"
)

type SampleParticipant struct {
	myIdentity             integration.IdentityKey
	mySharingId            int
	idToKey                map[int]integration.IdentityKey
	keyToId                map[types.IdentityHash]int
	parties                *hashset.HashSet[integration.IdentityKey]
	maximalUnqualifiedSets []*PartySubSet
	threshold              int
	prng                   io.Reader
	ra                     map[int]curves.Scalar
}

func (p *SampleParticipant) GetAuthKey() integration.AuthKey {
	return p.myIdentity.(integration.AuthKey)
}

func (p *SampleParticipant) GetSharingId() int {
	return p.mySharingId
}

func (p *SampleParticipant) GetCohortConfig() *integration.CohortConfig {
	return nil
}

var _ integration.Participant = (*SetupParticipant)(nil)

func NewSampleParticipant(myIdentity integration.IdentityKey, parties *hashset.HashSet[integration.IdentityKey], threshold int, ra map[int]curves.Scalar, prng io.Reader) (*SampleParticipant, error) {
	idToKey, keyToId, mySharingId := integration.DeriveSharingIds(myIdentity, parties)
	t := threshold - 1

	participant := &SampleParticipant{
		myIdentity:             myIdentity,
		mySharingId:            mySharingId,
		idToKey:                idToKey,
		keyToId:                keyToId,
		parties:                parties,
		maximalUnqualifiedSets: NewSubSets(parties, parties.Len()-t),
		threshold:              t,
		prng:                   prng,
		ra:                     ra,
	}

	return participant, nil
}
