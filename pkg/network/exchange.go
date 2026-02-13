package network

import (
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/errs-go/errs"
)

func SendUnicast[U any](rt *Router, correlationID string, messages RoundMessages[U]) error {
	messagesSerialized := make(map[sharing.ID][]byte)
	for id, message := range messages.Iter() {
		messageSerialized, err := serde.MarshalCBOR(message)
		if err != nil {
			return errs.Wrap(err).WithMessage("failed to marshal message")
		}
		messagesSerialized[id] = messageSerialized
	}
	err := rt.SendTo(correlationID, messagesSerialized)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to send messages")
	}
	return nil
}

func ReceiveUnicast[U any](rt *Router, correlationID string, quorum Quorum) (RoundMessages[U], error) {
	coparties := quorum.Clone().Unfreeze()
	coparties.Remove(rt.PartyID())

	receivedMessagesSerialized, err := rt.ReceiveFrom(correlationID, coparties.List()...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to exchange messages")
	}
	receivedMessages := make(map[sharing.ID]U)
	for id, m := range receivedMessagesSerialized {
		msg, err := serde.UnmarshalCBOR[U](m)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to unmarshal message")
		}
		receivedMessages[id] = msg
	}
	return hashmap.NewImmutableComparableFromNativeLike(receivedMessages), nil
}
