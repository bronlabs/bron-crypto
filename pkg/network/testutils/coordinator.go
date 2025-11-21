package ntu

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

const messageBufferSize = 128

type MockCoordinator struct {
	channels map[sharing.ID]chan deliveryMessage
}

func NewMockCoordinator(quorum ...sharing.ID) *MockCoordinator {
	channels := make(map[sharing.ID]chan deliveryMessage)
	for _, p := range quorum {
		channels[p] = make(chan deliveryMessage, messageBufferSize)
	}
	return &MockCoordinator{channels: channels}
}

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

func (d *mockDelivery) PartyId() sharing.ID {
	return d.sharingId
}

func (d *mockDelivery) Quorum() []sharing.ID {
	return d.quorum
}

func (d *mockDelivery) Send(sharingId sharing.ID, payload []byte) error {
	payloadClone := make([]byte, len(payload))
	copy(payloadClone, payload)
	sendChan, ok := d.sendChannels[sharingId]
	if !ok {
		return errs.NewFailed("no channel for recipient")
	}

	sendChan <- deliveryMessage{
		From:    d.sharingId,
		Payload: payloadClone,
	}
	return nil
}

func (d *mockDelivery) Receive() (from sharing.ID, payload []byte, err error) {
	msg := <-d.receiveChannel
	return msg.From, msg.Payload, nil
}
