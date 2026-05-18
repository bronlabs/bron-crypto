package network

import (
	"context"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

func SendUnicast[U Message[P], P any](ctx context.Context, rt *Router, correlationID string, messages RoundMessages[U, P]) error {
	messagesSerialized := make(map[sharing.ID][]byte)
	for id, message := range messages.Iter() {
		messageSerialized, err := serde.MarshalCBOR(message)
		if err != nil {
			return errs.Wrap(err).WithMessage("failed to marshal message")
		}
		messagesSerialized[id] = messageSerialized
	}
	err := rt.SendTo(ctx, correlationID, messagesSerialized)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to send messages")
	}
	return nil
}

func ReceiveUnicast[U Message[P], P any](ctx context.Context, rt *Router, correlationID string, quorum Quorum) (RoundMessages[U, P], error) {
	coparties := quorum.Clone().Unfreeze()
	coparties.Remove(rt.PartyID())

	receivedMessagesSerialized, err := rt.ReceiveFrom(ctx, correlationID, coparties.List()...)
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
