package network

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Router interface {
	PartyId() sharing.ID
	Quorum() []sharing.ID
	Send(correlationId string, messages map[sharing.ID][]byte) error
	Receive(correlationId string, from ...sharing.ID) (map[sharing.ID][]byte, error)
}

// ExchangeUnicastSimple sends messages to all participants and receives the same messages back from them.
func ExchangeUnicastSimple[U any](router Router, correlationId string, messages map[sharing.ID]U) (map[sharing.ID]U, error) {
	messagesSerialized := make(map[sharing.ID][]byte)
	for _, id := range router.Quorum() {
		if id == router.PartyId() {
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
	err := router.Send(correlationId, messagesSerialized)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to send messages")
	}

	coparties := slices.Collect(maps.Keys(messagesSerialized))
	receivedMessagesSerialized, err := router.Receive(correlationId, coparties...)
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
func ExchangeBroadcastSimple[B any](router Router, correlationId string, message B) (map[sharing.ID]B, error) {
	messageSerialized, err := serde.MarshalCBOR(message)
	if err != nil {
		return nil, errs.NewFailed("failed to marshal message")
	}
	messagesSerialized := make(map[sharing.ID][]byte)
	for _, id := range router.Quorum() {
		if id == router.PartyId() {
			continue
		}
		messagesSerialized[id] = messageSerialized
	}
	err = router.Send(correlationId, messagesSerialized)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to send messages")
	}

	coparties := slices.Collect(maps.Keys(messagesSerialized))
	receivedMessagesSerialized, err := router.Receive(correlationId, coparties...)
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
