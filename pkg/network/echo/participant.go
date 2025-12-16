package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// Participant drives the echo broadcast protocol for a single party.
type Participant[B any] struct {
	sharingId sharing.ID
	quorum    network.Quorum
	state     state
}

type state struct {
	messages map[sharing.ID][]byte
}

func NewParticipant[B any](id sharing.ID, quorum network.Quorum) (*Participant[B], error) {
	if quorum == nil || !quorum.Contains(id) {
		return nil, errs.NewMembership("sharingId not in quorum")
	}

	p := &Participant[B]{
		sharingId: id,
		quorum:    quorum,
		state: state{
			messages: make(map[sharing.ID][]byte),
		},
	}
	return p, nil
}

// SharingID returns the participant's identifier.
func (p *Participant[B]) SharingID() sharing.ID {
	return p.sharingId
}

// Quorum returns the participant quorum.
func (p *Participant[B]) Quorum() network.Quorum {
	return p.quorum
}
