package network

import (
	"bytes"
	"context"
	"sync"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Delivery abstracts a transport layer used by the router.
//
// Send must be safe for concurrent use by multiple goroutines. Receive is only
// ever called sequentially from the router's single reader goroutine;
// honouring context cancellation in Receive lets Close release that goroutine
// promptly.
type Delivery interface {
	PartyID() sharing.ID
	Quorum() []sharing.ID
	Send(ctx context.Context, to sharing.ID, message []byte) error
	Receive(ctx context.Context) (from sharing.ID, message []byte, err error)
}

// maxReceiveBufferSize caps the number of undelivered messages the router will
// buffer across all correlation IDs. It bounds memory usage when peers (or a
// compromised transport) inject messages with unexpected correlation IDs or
// sender identities.
const maxReceiveBufferSize = 10000

// namespaceSeparator joins Namespaced prefixes with correlation IDs on the
// wire. Protocol correlation IDs must not contain it.
const namespaceSeparator = "/"

// Router orchestrates correlation-aware sending and receiving over a Delivery.
//
// A Router is safe for concurrent use: any number of goroutines may call
// SendTo and ReceiveFrom simultaneously, as long as no two ReceiveFrom calls
// wait on the same correlation ID at once. A single reader goroutine, started
// lazily by the first ReceiveFrom, owns Delivery.Receive and demultiplexes
// incoming messages into per-correlation-ID mailboxes. The reader stops at the
// first delivery failure, decode failure, or buffer overflow; that failure is
// latched and returned to every pending and subsequent ReceiveFrom. Call
// Close once the router is no longer needed, otherwise the reader goroutine
// lives until the delivery fails.
type Router struct {
	core   *routerCore
	prefix string
}

// NewRouter wraps a Delivery with buffering and correlation-aware routing.
func NewRouter(delivery Delivery) *Router {
	return &Router{
		core: &routerCore{
			delivery:  delivery,
			quorumSet: hashset.NewComparable(delivery.Quorum()...).Freeze(),
			mu:        sync.Mutex{},
			boxes:     make(map[string]*mailbox),
			buffered:  0,
			started:   false,
			stop:      nil,
			fatal:     nil,
			failed:    make(chan struct{}),
		},
		prefix: "",
	}
}

// Namespaced returns a view of the router that prefixes every correlation ID
// with the given namespace, letting concurrent protocol runs that reuse the
// same static correlation IDs share one delivery. All views share the reader,
// buffers, and lifecycle of the parent router, and Close on any view stops
// them all. All parties of a protocol run must use the same namespace.
// Namespaces and protocol correlation IDs must not contain "/".
func (r *Router) Namespaced(namespace string) *Router {
	return &Router{
		core:   r.core,
		prefix: r.prefix + namespace + namespaceSeparator,
	}
}

// SendTo serialises and sends messages to the given recipients under a correlation identifier.
func (r *Router) SendTo(ctx context.Context, correlationID string, messages map[sharing.ID][]byte) error {
	for id, payload := range messages {
		//nolint:exhaustruct // From is optional
		message := routerMessage{
			CorrelationID: r.prefix + correlationID,
			Payload:       payload,
		}
		serializedMessage, err := serde.MarshalCBOR(&message)
		if err != nil {
			return errs.Wrap(err).WithMessage("failed to marshal message")
		}
		if err := r.core.delivery.Send(ctx, id, serializedMessage); err != nil {
			return errs.Wrap(err).WithMessage("failed to send message")
		}
	}

	return nil
}

// ReceiveFrom collects messages matching the correlation identifier from the
// specified senders, buffering unrelated messages for later retrieval. It
// blocks until every requested sender has delivered a message, the context is
// cancelled, or the router fails. Messages already buffered for the
// correlation ID survive a cancelled call, so a retry with the same arguments
// resumes where it left off.
func (r *Router) ReceiveFrom(ctx context.Context, correlationID string, froms ...sharing.ID) (map[sharing.ID][]byte, error) {
	return r.core.receiveFrom(ctx, r.prefix+correlationID, froms)
}

// PartyID returns the router's local party identifier.
func (r *Router) PartyID() sharing.ID {
	return r.core.delivery.PartyID()
}

// Quorum returns the identifiers of all parties in the session.
func (r *Router) Quorum() []sharing.ID {
	return r.core.delivery.Quorum()
}

// Close stops the reader goroutine and fails all pending and future
// ReceiveFrom calls with ErrRouterClosed. It does not close the underlying
// delivery and does not affect SendTo. Close is idempotent and safe for
// concurrent use.
func (r *Router) Close() {
	r.core.shutdown()
}

// routerCore is the state shared by all namespaced views of one router.
type routerCore struct {
	delivery  Delivery
	quorumSet ds.Set[sharing.ID]

	mu       sync.Mutex
	boxes    map[string]*mailbox
	buffered int
	started  bool
	stop     context.CancelFunc
	fatal    error
	failed   chan struct{}
}

// mailbox accumulates the messages of one correlation ID, keyed by sender.
// Payloads stay in the mailbox until a ReceiveFrom call has collected its full
// expected set, so the reader can detect conflicting duplicates and cancelled
// calls lose nothing.
type mailbox struct {
	payloads map[sharing.ID][]byte
	poison   error
	notify   chan struct{}
}

// signal wakes the attached waiter, if any, without blocking the reader. The
// waiter re-scans the mailbox under the lock after every wake-up, so a single
// buffered token cannot miss state changes.
func (b *mailbox) signal() {
	if b.notify == nil {
		return
	}
	select {
	case b.notify <- struct{}{}:
	default:
	}
}

func (c *routerCore) receiveFrom(ctx context.Context, correlationID string, froms []sharing.ID) (map[sharing.ID][]byte, error) {
	expected := hashset.NewComparable(froms...)

	c.mu.Lock()
	if c.fatal != nil {
		fatal := c.fatal
		c.mu.Unlock()
		return nil, errs.Wrap(fatal).WithMessage("failed to receive message")
	}
	if !c.started {
		c.started = true
		readerCtx, cancel := context.WithCancel(context.Background())
		c.stop = cancel
		go c.readLoop(readerCtx)
	}
	box := c.boxFor(correlationID)
	if box.notify != nil {
		c.mu.Unlock()
		return nil, ErrInvalidArgument.WithMessage("concurrent ReceiveFrom calls share correlation ID %q", correlationID)
	}
	notify := make(chan struct{}, 1)
	box.notify = notify
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		box.notify = nil
		if len(box.payloads) == 0 && box.poison == nil {
			delete(c.boxes, correlationID)
		}
		c.mu.Unlock()
	}()

	// All outcomes are decided in the locked scan with a fixed priority —
	// poison, then a complete set, then a latched failure, then cancellation —
	// so a set completed before a failure or cancellation is still delivered
	// no matter which wake-up fires first.
	for {
		c.mu.Lock()
		if box.poison != nil {
			poison := box.poison
			c.mu.Unlock()
			return nil, poison
		}
		received := make(map[sharing.ID][]byte, expected.Size())
		complete := true
		for from := range expected.Iter() {
			payload, ok := box.payloads[from]
			if !ok {
				complete = false
				break
			}
			received[from] = payload
		}
		if complete {
			for from := range expected.Iter() {
				delete(box.payloads, from)
			}
			c.buffered -= expected.Size()
			c.mu.Unlock()
			return received, nil
		}
		if c.fatal != nil {
			fatal := c.fatal
			c.mu.Unlock()
			return nil, errs.Wrap(fatal).WithMessage("failed to receive message")
		}
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return nil, errs.Wrap(err).WithMessage("failed to receive message")
		}
		c.mu.Unlock()

		select {
		case <-notify:
		case <-ctx.Done():
		case <-c.failed:
		}
	}
}

func (c *routerCore) readLoop(ctx context.Context) {
	defer func() {
		if recovered := recover(); recovered != nil {
			c.fail(errs.New("router reader panicked: %v", recovered))
		}
	}()

	for {
		from, serializedMessage, err := c.delivery.Receive(ctx)
		if err != nil {
			c.fail(errs.Wrap(err).WithMessage("failed to receive message"))
			return
		}
		// Drop messages from senders outside the session quorum. A compromised
		// transport layer could otherwise spoof messages from arbitrary IDs.
		if !c.quorumSet.Contains(from) {
			continue
		}
		message, err := serde.UnmarshalCBOR[routerMessage](serializedMessage)
		if err != nil {
			c.fail(errs.Wrap(err).WithMessage("failed to decode message"))
			return
		}
		if !c.deposit(from, message) {
			return
		}
	}
}

// deposit files an incoming message into its correlation mailbox. It reports
// false when the router latched a fatal error and the reader must stop.
func (c *routerCore) deposit(from sharing.ID, message routerMessage) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	box := c.boxFor(message.CorrelationID)
	if existing, ok := box.payloads[from]; ok {
		// If parties send two different messages with the same correlation ID, that's a byzantine behaviour.
		if !bytes.Equal(existing, message.Payload) {
			box.poison = ErrDuplicateMessage.WithTag(base.IdentifiableAbortPartyIDTag, from).WithMessage("conflicting messages received from sender %d", from)
			box.signal()
		}
		return true
	}
	if c.buffered >= maxReceiveBufferSize {
		c.failLocked(ErrReceiveBufferFull.WithMessage("receive buffer exceeded %d messages", maxReceiveBufferSize))
		return false
	}
	box.payloads[from] = message.Payload
	c.buffered++
	box.signal()
	return true
}

func (c *routerCore) boxFor(correlationID string) *mailbox {
	box, ok := c.boxes[correlationID]
	if !ok {
		box = &mailbox{
			payloads: make(map[sharing.ID][]byte),
			poison:   nil,
			notify:   nil,
		}
		c.boxes[correlationID] = box
	}
	return box
}

func (c *routerCore) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failLocked(err)
}

func (c *routerCore) failLocked(err error) {
	if c.fatal != nil {
		return
	}
	c.fatal = err
	close(c.failed)
}

func (c *routerCore) shutdown() {
	c.mu.Lock()
	stop := c.stop
	c.failLocked(ErrRouterClosed)
	c.mu.Unlock()
	if stop != nil {
		stop()
	}
}

type routerMessage struct {
	From          sharing.ID `cbor:"from"`
	CorrelationID string     `cbor:"correlationID"`
	Payload       []byte     `cbor:"payload"`
}
