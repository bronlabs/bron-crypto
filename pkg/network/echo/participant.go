package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// Participant drives the echo broadcast protocol for a single party.
type Participant[B any] struct {
	sharingID sharing.ID
	quorum    network.Quorum
	state     state
}

type state struct {
	messages map[sharing.ID][]byte
}

func NewParticipant[B any](id sharing.ID, quorum network.Quorum) (*Participant[B], error) {
	if quorum == nil || !quorum.Contains(id) {
		return nil, ErrInvalidArgument.WithMessage("sharingID not in quorum")
	}

	p := &Participant[B]{
		sharingID: id,
		quorum:    quorum,
		state: state{
			messages: make(map[sharing.ID][]byte),
		},
	}
	return p, nil
}

// SharingID returns the participant's identifier.
func (p *Participant[B]) SharingID() sharing.ID {
	return p.sharingID
}

// Quorum returns the participant quorum.
func (p *Participant[B]) Quorum() network.Quorum {
	return p.quorum
}
