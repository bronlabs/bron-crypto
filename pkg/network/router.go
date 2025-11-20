package network

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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

func (r *Router) sendTo(correlationId string, messages map[sharing.ID][]byte) error {
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

func (r *Router) receiveFrom(correlationId string, froms ...sharing.ID) (map[sharing.ID][]byte, error) {
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

// ExchangeUnicastSimple sends messages to all participants and receives the same messages back from them.
func ExchangeUnicastSimple[U any](router *Router, correlationId string, messages map[sharing.ID]U) (map[sharing.ID]U, error) {
	messagesSerialized := make(map[sharing.ID][]byte)
	for _, id := range router.delivery.Quorum() {
		if id == router.delivery.PartyId() {
			continue
		}
		message, ok := messages[id]
		if !ok {
			return nil, errs.NewFailed("missing message")
		}
		messageSerialized, err := serde.MarshalCBOR(message)
		if err != nil {
			return nil, errs.WrapSerialisation(err, "failed to marshal message")
		}
		messagesSerialized[id] = messageSerialized

	}
	err := router.sendTo(correlationId, messagesSerialized)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to send messages")
	}

	coparties := slices.Collect(maps.Keys(messagesSerialized))
	receivedMessagesSerialized, err := router.receiveFrom(correlationId, coparties...)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to exchange messages")
	}
	receivedMessages := make(map[sharing.ID]U)
	for id, m := range receivedMessagesSerialized {
		msg, err := serde.UnmarshalCBOR[U](m)
		if err != nil {
			return nil, errs.WrapSerialisation(err, "failed to unmarshal message")
		}
		receivedMessages[id] = msg
	}
	return receivedMessages, nil
}

// ExchangeBroadcastSimple sends a message to all participants and receives the same message back from them.
func ExchangeBroadcastSimple[B any](router *Router, correlationId string, message B) (map[sharing.ID]B, error) {
	messageSerialized, err := serde.MarshalCBOR(message)
	if err != nil {
		return nil, errs.NewFailed("failed to marshal message")
	}
	messagesSerialized := make(map[sharing.ID][]byte)
	for _, id := range router.delivery.Quorum() {
		if id == router.delivery.PartyId() {
			continue
		}
		messagesSerialized[id] = messageSerialized
	}
	err = router.sendTo(correlationId, messagesSerialized)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to send messages")
	}

	coparties := slices.Collect(maps.Keys(messagesSerialized))
	receivedMessagesSerialized, err := router.receiveFrom(correlationId, coparties...)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to receive messages")
	}
	receivedMessages := make(map[sharing.ID]B)
	for id, m := range receivedMessagesSerialized {
		msg, err := serde.UnmarshalCBOR[B](m)
		if err != nil {
			return nil, errs.WrapSerialisation(err, "failed to unmarshal message")
		}
		receivedMessages[id] = msg
	}
	return receivedMessages, nil
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
