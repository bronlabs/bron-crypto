package network

import (
	"bytes"
	"context"
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
	Send(ctx context.Context, to sharing.ID, message []byte) error
	Receive(ctx context.Context) (from sharing.ID, message []byte, err error)
}

const (
	defaultMaxFrameBytes         = 16 << 20
	defaultMaxPayloadBytes       = 16 << 20
	defaultMaxCorrelationIDBytes = 1024
	defaultMaxBufferedMessages   = 10000
	defaultMaxBufferedBytes      = 128 << 20
)

// RouterOptions bounds untrusted transport input and retained out-of-order messages.
// Zero-valued fields use production defaults.
type RouterOptions struct {
	MaxFrameBytes         int
	MaxPayloadBytes       int
	MaxCorrelationIDBytes int
	MaxBufferedMessages   int
	MaxBufferedBytes      int
}

// Router orchestrates correlation-aware sending and receiving over a Delivery.
type Router struct {
	receiveBuffer      []routerMessage
	receiveBufferBytes int
	delivery           Delivery
	options            RouterOptions
	quorumSet          ds.Set[sharing.ID]
}

// NewRouter wraps a Delivery with buffering and correlation-aware routing.
func NewRouter(delivery Delivery) *Router {
	//nolint:exhaustruct // zero-valued options request production defaults.
	return NewRouterWithOptions(delivery, RouterOptions{})
}

// NewRouterWithOptions wraps a Delivery with buffering and bounded correlation-aware routing.
func NewRouterWithOptions(delivery Delivery, options RouterOptions) *Router {
	return &Router{
		receiveBuffer:      nil,
		receiveBufferBytes: 0,
		delivery:           delivery,
		options:            options.withDefaults(),
		quorumSet:          hashset.NewComparable(delivery.Quorum()...).Freeze(),
	}
}

// SendTo serialises and sends messages to the given recipients under a correlation identifier.
func (r *Router) SendTo(ctx context.Context, correlationID string, messages map[sharing.ID][]byte) error {
	if len(correlationID) > r.options.MaxCorrelationIDBytes {
		return ErrCorrelationIDTooLarge.WithMessage("correlation id exceeded %d bytes", r.options.MaxCorrelationIDBytes)
	}
	for id, payload := range messages {
		if len(payload) > r.options.MaxPayloadBytes {
			return ErrPayloadTooLarge.WithMessage("payload exceeded %d bytes", r.options.MaxPayloadBytes)
		}
		//nolint:exhaustruct // From is optional
		message := routerMessage{
			CorrelationID: correlationID,
			Payload:       payload,
		}
		serializedMessage, err := serde.MarshalCBOR(&message)
		if err != nil {
			return errs.Wrap(err).WithMessage("failed to marshal message")
		}
		if len(serializedMessage) > r.options.MaxFrameBytes {
			return ErrFrameTooLarge.WithMessage("frame exceeded %d bytes", r.options.MaxFrameBytes)
		}
		if err := r.delivery.Send(ctx, id, serializedMessage); err != nil {
			return errs.Wrap(err).WithMessage("failed to send message")
		}
	}

	return nil
}

// ReceiveFrom collects messages matching the correlation identifier from the specified senders,
// buffering unrelated messages for later retrieval.
func (r *Router) ReceiveFrom(ctx context.Context, correlationID string, froms ...sharing.ID) (map[sharing.ID][]byte, error) {
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
	r.receiveBufferBytes = bufferedMessagesBytes(kept)

	for !sliceutils.IsSuperSet(slices.Collect(maps.Keys(received)), froms) {
		from, serializedMessage, err := r.delivery.Receive(ctx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to receive message")
		}
		// Drop messages from senders outside the session quorum. A compromised
		// transport layer could otherwise spoof messages from arbitrary IDs.
		if !r.quorumSet.Contains(from) {
			continue
		}
		if len(serializedMessage) > r.options.MaxFrameBytes {
			return nil, ErrFrameTooLarge.WithMessage("frame exceeded %d bytes", r.options.MaxFrameBytes)
		}
		message, err := serde.UnmarshalCBOR[routerMessage](serializedMessage)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to decode message")
		}
		if err := r.validateMessage(message); err != nil {
			return nil, err
		}

		if message.CorrelationID == correlationID {
			if _, ok := expected[from]; !ok {
				message.From = from
				if err := r.bufferMessage(message); err != nil {
					return nil, err
				}
				continue
			}

			// If parties send two different messages with the same correlation ID, that's a byzantine behaviour.
			alreadyReceived, exists := received[from]
			if exists && !bytes.Equal(alreadyReceived, message.Payload) {
				return nil, ErrDuplicateMessage.WithTag(base.IdentifiableAbortPartyIDTag, from).WithMessage("conflicting messages received from sender %d", from)
			}
			received[from] = message.Payload
		} else {
			message.From = from
			if err := r.bufferMessage(message); err != nil {
				return nil, err
			}
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

func (options RouterOptions) withDefaults() RouterOptions {
	if options.MaxFrameBytes <= 0 {
		options.MaxFrameBytes = defaultMaxFrameBytes
	}
	if options.MaxPayloadBytes <= 0 {
		options.MaxPayloadBytes = defaultMaxPayloadBytes
	}
	if options.MaxCorrelationIDBytes <= 0 {
		options.MaxCorrelationIDBytes = defaultMaxCorrelationIDBytes
	}
	if options.MaxBufferedMessages <= 0 {
		options.MaxBufferedMessages = defaultMaxBufferedMessages
	}
	if options.MaxBufferedBytes <= 0 {
		options.MaxBufferedBytes = defaultMaxBufferedBytes
	}
	return options
}

func (r *Router) validateMessage(message routerMessage) error {
	if len(message.Payload) > r.options.MaxPayloadBytes {
		return ErrPayloadTooLarge.WithMessage("payload exceeded %d bytes", r.options.MaxPayloadBytes)
	}
	if len(message.CorrelationID) > r.options.MaxCorrelationIDBytes {
		return ErrCorrelationIDTooLarge.WithMessage("correlation id exceeded %d bytes", r.options.MaxCorrelationIDBytes)
	}
	return nil
}

func (r *Router) bufferMessage(message routerMessage) error {
	if len(r.receiveBuffer) >= r.options.MaxBufferedMessages {
		return ErrReceiveBufferFull.WithMessage("receive buffer exceeded %d messages", r.options.MaxBufferedMessages)
	}
	messageBytes := bufferedMessageBytes(message)
	if messageBytes > r.options.MaxBufferedBytes || r.receiveBufferBytes > r.options.MaxBufferedBytes-messageBytes {
		return ErrReceiveBufferFull.WithMessage("receive buffer exceeded %d bytes", r.options.MaxBufferedBytes)
	}
	r.receiveBuffer = append(r.receiveBuffer, message)
	r.receiveBufferBytes += messageBytes
	return nil
}

func bufferedMessagesBytes(messages []routerMessage) int {
	total := 0
	for _, message := range messages {
		total += bufferedMessageBytes(message)
	}
	return total
}

func bufferedMessageBytes(message routerMessage) int {
	return len(message.CorrelationID) + len(message.Payload)
}
