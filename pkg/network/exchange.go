package network

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// ExchangeUnicastSimple sends messages to all participants and receives the same messages back from them.
func ExchangeUnicastSimple[U any](rt *Router, correlationId string, messages RoundMessages[U]) (RoundMessages[U], error) {
	messagesSerialized := make(map[sharing.ID][]byte)
	for _, id := range rt.Quorum() {
		if id == rt.PartyId() {
			continue
		}
		message, ok := messages.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message")
		}
		messageSerialized, err := serde.MarshalCBOR(message)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to marshal message")
		}
		messagesSerialized[id] = messageSerialized
	}
	err := rt.SendTo(correlationId, messagesSerialized)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to send messages")
	}

	coparties := slices.Collect(maps.Keys(messagesSerialized))
	receivedMessagesSerialized, err := rt.ReceiveFrom(correlationId, coparties...)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to exchange messages")
	}
	receivedMessages := make(map[sharing.ID]U)
	for id, m := range receivedMessagesSerialized {
		msg, err := serde.UnmarshalCBOR[U](m)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to unmarshal message")
		}
		receivedMessages[id] = msg
	}
	return hashmap.NewImmutableComparableFromNativeLike(receivedMessages), nil
}

func ExchangeUnicastRing[U any](rt *Router, correlationId string, prevId, nextId sharing.ID, message U) (U, error) {
	var nilU U
	messageSerialized, err := serde.MarshalCBOR(message)
	if err != nil {
		return nilU, errs.WrapSerialisation(err, "failed to marshal message")
	}
	err = rt.SendTo(correlationId, map[sharing.ID][]byte{nextId: messageSerialized})
	if err != nil {
		return nilU, errs.WrapFailed(err, "failed to send message")
	}
	receivedMessageSerialized, err := rt.ReceiveFrom(correlationId, prevId)
	if err != nil {
		return nilU, errs.WrapFailed(err, "failed to exchange message")
	}
	receivedMessage, err := serde.UnmarshalCBOR[U](receivedMessageSerialized[prevId])
	if err != nil {
		return nilU, errs.WrapSerialisation(err, "failed to unmarshal message")
	}
	return receivedMessage, nil
}

func SendUnicast[U any](rt *Router, correlationId string, messages RoundMessages[U]) error {
	messagesSerialized := make(map[sharing.ID][]byte)
	for _, id := range rt.Quorum() {
		if id == rt.PartyId() {
			continue
		}
		message, ok := messages.Get(id)
		if !ok {
			continue
		}

		messageSerialized, err := serde.MarshalCBOR(message)
		if err != nil {
			return errs.WrapSerialisation(err, "failed to marshal message")
		}
		messagesSerialized[id] = messageSerialized
	}
	err := rt.SendTo(correlationId, messagesSerialized)
	if err != nil {
		return errs.WrapFailed(err, "failed to send messages")
	}

	return nil
}

func ReceiveUnicast[U any](rt *Router, correlationId string, from ...sharing.ID) (RoundMessages[U], error) {
	receivedMessagesSerialized, err := rt.ReceiveFrom(correlationId, from...)
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
	return hashmap.NewImmutableComparableFromNativeLike(receivedMessages), nil
}
