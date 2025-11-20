package network

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Delivery interface {
	PartyId() sharing.ID
	Quorum() []sharing.ID
	Send(to sharing.ID, message []byte) error
	Receive() (from sharing.ID, message []byte, err error)
}

type Router struct {
	receiveBuffer []routerMessage
	delivery      Delivery
}

func NewRouter(delivery Delivery) *Router {
	return &Router{
		delivery: delivery,
	}
}

func (r *Router) SendTo(correlationId string, messages map[sharing.ID][]byte) error {
	for id, payload := range messages {
		message := routerMessage{
			CorrelationId: correlationId,
			Payload:       payload,
		}
		serializedMessage, err := serde.MarshalCBOR(&message)
		if err != nil {
			return err
		}
		if err := r.delivery.Send(id, serializedMessage); err != nil {
			return err
		}
	}

	return nil
}

func (r *Router) ReceiveFrom(correlationId string, froms ...sharing.ID) (map[sharing.ID][]byte, error) {
	received := make(map[sharing.ID][]byte)
	var kept []routerMessage
	for _, bufferedMsg := range r.receiveBuffer {
		if bufferedMsg.CorrelationId == correlationId {
			received[bufferedMsg.From] = bufferedMsg.Payload
		} else {
			kept = append(kept, bufferedMsg)
		}
	}
	r.receiveBuffer = kept

	for !containsAll(slices.Collect(maps.Keys(received)), froms) {
		from, serializedMessage, err := r.delivery.Receive()
		if err != nil {
			return nil, err
		}
		message, err := serde.UnmarshalCBOR[routerMessage](serializedMessage)
		if err != nil {
			return nil, err
		}

		if message.CorrelationId == correlationId {
			received[from] = message.Payload
		} else {
			message.From = from
			r.receiveBuffer = append(r.receiveBuffer, message)
		}
	}
	return received, nil
}

func (r *Router) PartyId() sharing.ID {
	return r.delivery.PartyId()
}

func (r *Router) Quorum() []sharing.ID {
	return r.delivery.Quorum()
}

// TODO: Implement ExchangeEchoBroadcastSimple etc.

type routerMessage struct {
	From          sharing.ID `cbor:"from"`
	CorrelationId string     `cbor:"correlationId"`
	Payload       []byte     `cbor:"payload"`
}

func containsAll(s []sharing.ID, ei []sharing.ID) bool {
	for _, e := range ei {
		if !slices.Contains(s, e) {
			return false
		}
	}
	return true
}
