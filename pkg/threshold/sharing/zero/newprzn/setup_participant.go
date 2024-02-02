package newprzn

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"io"
)

type SetupParticipant struct {
	field                  curves.ScalarField
	myIdentity             integration.IdentityKey
	mySharingId            int
	parties                *hashset.HashSet[integration.IdentityKey]
	maximalUnqualifiedSets []*SubSet
	threshold              int
	prng                   io.Reader
	state                  *state
}

func (p *SetupParticipant) GetAuthKey() integration.AuthKey {
	return p.myIdentity.(integration.AuthKey)
}

func (p *SetupParticipant) GetSharingId() int {
	return p.mySharingId
}

func (p *SetupParticipant) GetCohortConfig() *integration.CohortConfig {
	return nil
}

var _ integration.Participant = (*SetupParticipant)(nil)

type state struct {
	ra map[int]curves.Scalar
}

func NewSetupParticipant(field curves.ScalarField, myIdentity integration.IdentityKey, parties *hashset.HashSet[integration.IdentityKey], threshold int, prng io.Reader) (*SetupParticipant, error) {
	_, _, mySharingId := integration.DeriveSharingIds(myIdentity, parties)
	t := threshold - 1

	participant := &SetupParticipant{
		field:                  field,
		myIdentity:             myIdentity,
		mySharingId:            mySharingId,
		parties:                parties,
		maximalUnqualifiedSets: NewSubSets(parties, parties.Len()-t),
		threshold:              t,
		prng:                   prng,
		state:                  &state{},
	}

	return participant, nil
}
