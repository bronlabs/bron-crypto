package testutils

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type MockCoordinator struct {
	channels map[sharing.ID]chan message
}

func NewMockCoordinator(quorum ...sharing.ID) *MockCoordinator {
	channels := make(map[sharing.ID]chan message)
	for _, p := range quorum {
		channels[p] = make(chan message, 128)
	}
	return &MockCoordinator{channels: channels}
}

func (c *MockCoordinator) RouterFor(sharingId sharing.ID) network.Router {
	recv := c.channels[sharingId]
	send := make(map[sharing.ID]chan<- message)
	for id, ch := range c.channels {
		if id == sharingId {
			continue
		}
		send[id] = ch
	}

	return &MockRouter{
		sharingId:      sharingId,
		quorum:         slices.Collect(maps.Keys(c.channels)),
		receiveChannel: recv,
		sendChannels:   send,
	}
}

type MockRouter struct {
	buffer         []message
	sharingId      sharing.ID
	quorum         []sharing.ID
	receiveChannel <-chan message
	sendChannels   map[sharing.ID]chan<- message
}

var _ network.Router = (*MockRouter)(nil)

func (r *MockRouter) Send(correlationId string, unicastMessages map[sharing.ID][]byte) error {
	for id, msg := range unicastMessages {
		ch, ok := r.sendChannels[id]
		if !ok {
			return errs.NewFailed("no channel for recipient")
		}
		unicastMessageClone := make([]byte, len(msg))
		copy(unicastMessageClone, msg)
		ch <- message{
			correlationId: correlationId,
			from:          r.sharingId,
			payload:       unicastMessageClone,
		}
	}
	return nil
}

func (r *MockRouter) Receive(correlationId string, from ...sharing.ID) (map[sharing.ID][]byte, error) {
	received := make(map[sharing.ID][]byte)
	var kept []message
	for _, bufferedMsg := range r.buffer {
		if bufferedMsg.correlationId == correlationId {
			received[bufferedMsg.from] = bufferedMsg.payload
		} else {
			kept = append(kept, bufferedMsg)
		}
	}
	r.buffer = kept

	for !containsAll(slices.Collect(maps.Keys(received)), from) {
		msg := <-r.receiveChannel
		if msg.correlationId == correlationId {
			received[msg.from] = msg.payload
		} else {
			r.buffer = append(r.buffer, msg)
		}
	}
	return received, nil
}

func (r *MockRouter) PartyId() sharing.ID {
	return r.sharingId
}

func (r *MockRouter) Quorum() []sharing.ID {
	return r.quorum
}

type message struct {
	from          sharing.ID
	correlationId string
	payload       []byte
}

func containsAll(s []sharing.ID, ei []sharing.ID) bool {
	for _, e := range ei {
		if !slices.Contains(s, e) {
			return false
		}
	}
	return true
}
