package network

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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
			return nil, errs.NewFailed("missing message")
		}
		messageSerialized, err := serde.MarshalCBOR(message)
		if err != nil {
			return nil, errs.WrapSerialisation(err, "failed to marshal message")
		}
		messagesSerialized[id] = messageSerialized
	}
	err := rt.SendTo(correlationId, messagesSerialized)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to send messages")
	}

	coparties := slices.Collect(maps.Keys(messagesSerialized))
	receivedMessagesSerialized, err := rt.ReceiveFrom(correlationId, coparties...)
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
