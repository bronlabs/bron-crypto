package network

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// Delivery abstracts a transport layer used by the router.
type Delivery interface {
	PartyId() sharing.ID
	Quorum() []sharing.ID
	Send(to sharing.ID, message []byte) error
	Receive() (from sharing.ID, message []byte, err error)
}

// Router orchestrates correlation-aware sending and receiving over a Delivery.
type Router struct {
	receiveBuffer []routerMessage
	delivery      Delivery
}

// NewRouter wraps a Delivery with buffering and correlation-aware routing.
func NewRouter(delivery Delivery) *Router {
	return &Router{
		receiveBuffer: nil,
		delivery:      delivery,
	}
}

// SendTo serialises and sends messages to the given recipients under a correlation identifier.
func (r *Router) SendTo(correlationId string, messages map[sharing.ID][]byte) error {
	for id, payload := range messages {
		//nolint:exhaustruct // From is optional
		message := routerMessage{
			CorrelationId: correlationId,
			Payload:       payload,
		}
		serializedMessage, err := serde.MarshalCBOR(&message)
		if err != nil {
			return errs2.Wrap(err).WithMessage("failed to marshal message")
		}
		if err := r.delivery.Send(id, serializedMessage); err != nil {
			return errs2.Wrap(err).WithMessage("failed to send message")
		}
	}

	return nil
}

// ReceiveFrom collects messages matching the correlation identifier from the specified senders,
// buffering unrelated messages for later retrieval.
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

	for !sliceutils.IsSuperSet(slices.Collect(maps.Keys(received)), froms) {
		from, serializedMessage, err := r.delivery.Receive()
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to receive message")
		}
		message, err := serde.UnmarshalCBOR[routerMessage](serializedMessage)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to decode message")
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

// PartyId returns the router's local party identifier.
func (r *Router) PartyId() sharing.ID {
	return r.delivery.PartyId()
}

// Quorum returns the identifiers of all parties in the session.
func (r *Router) Quorum() []sharing.ID {
	return r.delivery.Quorum()
}

type routerMessage struct {
	From          sharing.ID `cbor:"from"`
	CorrelationId string     `cbor:"correlationId"`
	Payload       []byte     `cbor:"payload"`
}
