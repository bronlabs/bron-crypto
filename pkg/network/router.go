package network

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// Delivery abstracts a transport layer used by the router.
type Delivery interface {
	PartyID() sharing.ID
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
func (r *Router) SendTo(correlationID string, messages map[sharing.ID][]byte) error {
	for id, payload := range messages {
		//nolint:exhaustruct // From is optional
		message := routerMessage{
			CorrelationID: correlationID,
			Payload:       payload,
		}
		serializedMessage, err := serde.MarshalCBOR(&message)
		if err != nil {
			return errs.Wrap(err).WithMessage("failed to marshal message")
		}
		if err := r.delivery.Send(id, serializedMessage); err != nil {
			return errs.Wrap(err).WithMessage("failed to send message")
		}
	}

	return nil
}

// ReceiveFrom collects messages matching the correlation identifier from the specified senders,
// buffering unrelated messages for later retrieval.
func (r *Router) ReceiveFrom(correlationID string, froms ...sharing.ID) (map[sharing.ID][]byte, error) {
	received := make(map[sharing.ID][]byte)
	var kept []routerMessage
	for _, bufferedMsg := range r.receiveBuffer {
		if bufferedMsg.CorrelationID == correlationID {
			received[bufferedMsg.From] = bufferedMsg.Payload
		} else {
			kept = append(kept, bufferedMsg)
		}
	}
	r.receiveBuffer = kept

	for !sliceutils.IsSuperSet(slices.Collect(maps.Keys(received)), froms) {
		from, serializedMessage, err := r.delivery.Receive()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to receive message")
		}
		message, err := serde.UnmarshalCBOR[routerMessage](serializedMessage)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to decode message")
		}

		if message.CorrelationID == correlationID {
			received[from] = message.Payload
		} else {
			message.From = from
			r.receiveBuffer = append(r.receiveBuffer, message)
		}
	}
	return received, nil
}

// PartyID returns the router's local party identifier.
func (r *Router) PartyID() sharing.ID {
	return r.delivery.PartyID()
}

// Quorum returns the identifiers of all parties in the session.
func (r *Router) Quorum() []sharing.ID {
	return r.delivery.Quorum()
}

type routerMessage struct {
	From          sharing.ID `cbor:"from"`
	CorrelationID string     `cbor:"correlationID"`
	Payload       []byte     `cbor:"payload"`
}
