package network

import (
	"bytes"
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Delivery abstracts a transport layer used by the router.
type Delivery interface {
	PartyID() sharing.ID
	Quorum() []sharing.ID
	Send(to sharing.ID, message []byte) error
	Receive() (from sharing.ID, message []byte, err error)
}

// maxReceiveBufferSize caps the number of out-of-order messages the router
// will buffer for later retrieval. It bounds memory usage when peers (or a
// compromised transport) inject messages with unexpected correlation IDs or
// sender identities.
const maxReceiveBufferSize = 10000

// Router orchestrates correlation-aware sending and receiving over a Delivery.
type Router struct {
	receiveBuffer []routerMessage
	delivery      Delivery
	quorumSet     ds.Set[sharing.ID]
}

// NewRouter wraps a Delivery with buffering and correlation-aware routing.
func NewRouter(delivery Delivery) *Router {
	return &Router{
		receiveBuffer: nil,
		delivery:      delivery,
		quorumSet:     hashset.NewComparable(delivery.Quorum()...).Freeze(),
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
	expected := map[sharing.ID]struct{}{}
	for _, from := range froms {
		expected[from] = struct{}{}
	}
	var kept []routerMessage
	for _, bufferedMsg := range r.receiveBuffer {
		if bufferedMsg.CorrelationID == correlationID {
			if _, ok := expected[bufferedMsg.From]; !ok {
				kept = append(kept, bufferedMsg)
				continue
			}
			// If parties send two different messages with the same correlation ID, that's a byzantine behaviour.
			alreadyReceived, exists := received[bufferedMsg.From]
			if exists && !bytes.Equal(alreadyReceived, bufferedMsg.Payload) {
				return nil, ErrDuplicateMessage.WithTag(base.IdentifiableAbortPartyIDTag, bufferedMsg.From).WithMessage("conflicting messages received from sender %d", bufferedMsg.From)
			}
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
		// Drop messages from senders outside the session quorum. A compromised
		// transport layer could otherwise spoof messages from arbitrary IDs.
		if !r.quorumSet.Contains(from) {
			continue
		}
		message, err := serde.UnmarshalCBOR[routerMessage](serializedMessage)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to decode message")
		}

		if message.CorrelationID == correlationID {
			if _, ok := expected[from]; !ok {
				if len(r.receiveBuffer) >= maxReceiveBufferSize {
					return nil, ErrReceiveBufferFull.WithMessage("receive buffer exceeded %d messages", maxReceiveBufferSize)
				}
				message.From = from
				r.receiveBuffer = append(r.receiveBuffer, message)
				continue
			}

			// If parties send two different messages with the same correlation ID, that's a byzantine behaviour.
			alreadyReceived, exists := received[from]
			if exists && !bytes.Equal(alreadyReceived, message.Payload) {
				return nil, ErrDuplicateMessage.WithTag(base.IdentifiableAbortPartyIDTag, from).WithMessage("conflicting messages received from sender %d", from)
			}
			received[from] = message.Payload
		} else {
			if len(r.receiveBuffer) >= maxReceiveBufferSize {
				return nil, ErrReceiveBufferFull.WithMessage("receive buffer exceeded %d messages", maxReceiveBufferSize)
			}
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
