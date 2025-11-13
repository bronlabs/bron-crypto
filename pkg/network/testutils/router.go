package testutils

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Coordinator interface {
	RouterFor(sharingId sharing.ID) Router
}

type Router interface {
	ExchangeBroadcast(correlationId string, message []byte, from ...sharing.ID) map[sharing.ID][]byte
	ExchangeUnicast(correlationId string, message map[sharing.ID][]byte, to ...sharing.ID) map[sharing.ID][]byte
}

func NewMockCoordinator(participants ...sharing.ID) Coordinator {
	channels := make(map[sharing.ID]chan mockMessage)
	for _, p := range participants {
		channels[p] = make(chan mockMessage, 128)
	}
	return &mockCoordinator{channels: channels}
}

func ExchangeBroadcast[B any](router Router, message B, from ...sharing.ID) map[sharing.ID]B {
	messageSerialized, err := serde.MarshalCBOR(message)
	if err != nil {
		panic(err)
	}
	receivedSerialized := router.ExchangeBroadcast(messageSerialized, from...)
	received := make(map[sharing.ID]B)
	for id, m := range receivedSerialized {
		msg, err := serde.UnmarshalCBOR[B](m)
		if err != nil {
			panic(err)
		}
		received[id] = msg
	}
	return received
}

func ExchangeUnicast[U any](router Router, message map[sharing.ID]U, to ...sharing.ID) map[sharing.ID]U {
	messageSerialized := make(map[sharing.ID][]byte)
	for id, m := range message {
		msg, err := serde.MarshalCBOR(m)
		if err != nil {
			panic(err)
		}
		messageSerialized[id] = msg
	}
	receivedSerialized := router.ExchangeUnicast(messageSerialized, to...)
	received := make(map[sharing.ID]U)
	for id, m := range receivedSerialized {
		msg, err := serde.UnmarshalCBOR[U](m)
		if err != nil {
			panic(err)
		}
		received[id] = msg
	}
	return received
}

type mockMessage struct {
	from          sharing.ID
	correlationId string
	payload       []byte
}

type mockCoordinator struct {
	channels map[sharing.ID]chan mockMessage
}

func (c *mockCoordinator) RouterFor(sharingId sharing.ID) Router {
	recv := c.channels[sharingId]
	send := make(map[sharing.ID]chan<- mockMessage)
	for id, ch := range c.channels {
		if id != sharingId {
			send[id] = ch
		}
	}

	return &mockRouter{
		sharingId:      sharingId,
		receiveChannel: recv,
		sendChannels:   send,
	}
}

var _ Coordinator = (*mockCoordinator)(nil)

type mockRouter struct {
	sharingId      sharing.ID
	receiveChannel <-chan mockMessage
	sendChannels   map[sharing.ID]chan<- mockMessage
}

var _ Router = (*mockRouter)(nil)

func (r *mockRouter) ExchangeBroadcast(message []byte, from ...sharing.ID) map[sharing.ID][]byte {
	for _, ch := range r.sendChannels {
		messageClone := make([]byte, len(message))
		copy(messageClone, message)
		msg := mockMessage{
			from:    r.sharingId,
			payload: messageClone,
		}
		ch <- msg
	}

	received := make(map[sharing.ID][]byte)
	for !containsAll(slices.Collect(maps.Keys(received)), from) {
		msg := <-r.receiveChannel
		received[msg.from] = msg.payload
	}
	return received
}

func (r *mockRouter) ExchangeUnicast(message map[sharing.ID][]byte, from ...sharing.ID) map[sharing.ID][]byte {
	for id, msg := range message {
		ch := r.sendChannels[id]
		msgClone := make([]byte, len(msg))
		copy(msgClone, msg)
		ch <- mockMessage{
			from:    r.sharingId,
			payload: msgClone,
		}
	}

	received := make(map[sharing.ID][]byte)
	for !containsAll(from, slices.Collect(maps.Keys(received))) {
		msg := <-r.receiveChannel
		received[msg.from] = msg.payload
	}
	return received
}

func containsAll(s []sharing.ID, ei []sharing.ID) bool {
	for _, e := range ei {
		if !slices.Contains(s, e) {
			return false
		}
	}
	return true
}
