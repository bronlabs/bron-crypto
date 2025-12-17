package ntu

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

const messageBufferSize = 128

// MockCoordinator simulates a reliable message hub using buffered channels.
type MockCoordinator struct {
	channels map[sharing.ID]chan deliveryMessage
}

// NewMockCoordinator allocates buffered in-memory channels for each party in the quorum.
func NewMockCoordinator(quorum ...sharing.ID) *MockCoordinator {
	channels := make(map[sharing.ID]chan deliveryMessage)
	for _, p := range quorum {
		channels[p] = make(chan deliveryMessage, messageBufferSize)
	}
	return &MockCoordinator{channels: channels}
}

// DeliveryFor returns a Delivery implementation bound to the given party.
func (c *MockCoordinator) DeliveryFor(sharingId sharing.ID) network.Delivery {
	recv := c.channels[sharingId]
	send := make(map[sharing.ID]chan<- deliveryMessage)
	for id, ch := range c.channels {
		if id == sharingId {
			continue
		}
		send[id] = ch
	}

	return &mockDelivery{
		sharingId:      sharingId,
		quorum:         slices.Collect(maps.Keys(c.channels)),
		receiveChannel: recv,
		sendChannels:   send,
	}
}

type deliveryMessage struct {
	From    sharing.ID `cbor:"from"`
	Payload []byte     `cbor:"payload"`
}

type mockDelivery struct {
	sharingId      sharing.ID
	quorum         []sharing.ID
	receiveChannel <-chan deliveryMessage
	sendChannels   map[sharing.ID]chan<- deliveryMessage
}

// PartyId returns the local party identifier.
func (d *mockDelivery) PartyId() sharing.ID {
	return d.sharingId
}

// Quorum returns the identifiers of the simulated quorum.
func (d *mockDelivery) Quorum() []sharing.ID {
	return d.quorum
}

// Send enqueues a message to the destination's channel.
func (d *mockDelivery) Send(sharingId sharing.ID, payload []byte) error {
	payloadClone := make([]byte, len(payload))
	copy(payloadClone, payload)
	sendChan, ok := d.sendChannels[sharingId]
	if !ok {
		return errs2.Wrap(network.ErrFailed).WithMessage("no channel for recipient")
	}

	sendChan <- deliveryMessage{
		From:    d.sharingId,
		Payload: payloadClone,
	}
	return nil
}

// Receive blocks until a message is available for the party.
func (d *mockDelivery) Receive() (from sharing.ID, payload []byte, err error) {
	msg := <-d.receiveChannel
	return msg.From, msg.Payload, nil
}
