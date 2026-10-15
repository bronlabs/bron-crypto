package network_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

var errStubTransport = errs.New("stub transport failure")

type wireMessage struct {
	From          sharing.ID `cbor:"from"`
	CorrelationID string     `cbor:"correlationID"`
	Payload       []byte     `cbor:"payload"`
}

type incomingMessage struct {
	from    sharing.ID
	message []byte
	err     error
}

type sentMessage struct {
	to      sharing.ID
	message []byte
}

type stubDelivery struct {
	partyID  sharing.ID
	quorum   []sharing.ID
	incoming chan incomingMessage

	mu   sync.Mutex
	sent []sentMessage
}

func newStubDelivery(quorum ...sharing.ID) *stubDelivery {
	return &stubDelivery{
		partyID:  1,
		quorum:   quorum,
		incoming: make(chan incomingMessage, 16384),
		mu:       sync.Mutex{},
		sent:     nil,
	}
}

func (d *stubDelivery) PartyID() sharing.ID {
	return d.partyID
}

func (d *stubDelivery) Quorum() []sharing.ID {
	return d.quorum
}

func (d *stubDelivery) Send(_ context.Context, to sharing.ID, message []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent = append(d.sent, sentMessage{to: to, message: message})
	return nil
}

func (d *stubDelivery) Receive(ctx context.Context) (sharing.ID, []byte, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case m := <-d.incoming:
		return m.from, m.message, m.err
	}
}

func (d *stubDelivery) deliver(tb require.TestingT, from sharing.ID, correlationID string, payload []byte) {
	raw, err := serde.MarshalCBOR(&wireMessage{CorrelationID: correlationID, Payload: payload})
	require.NoError(tb, err)
	d.incoming <- incomingMessage{from: from, message: raw, err: nil}
}

func (d *stubDelivery) failReceive(err error) {
	d.incoming <- incomingMessage{from: 0, message: nil, err: err}
}

func (d *stubDelivery) sentMessages() []sentMessage {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]sentMessage(nil), d.sent...)
}

func TestRouterReceiveFromFiltersUnexpectedSenders(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2, 3)
	delivery.deliver(t, 3, "cid", []byte("unexpected"))
	delivery.deliver(t, 2, "cid", []byte("expected"))

	router := network.NewRouter(delivery)
	defer router.Close()

	received, err := router.ReceiveFrom(context.Background(), "cid", 2)
	require.NoError(t, err)
	require.Equal(t, map[sharing.ID][]byte{2: []byte("expected")}, received)

	received, err = router.ReceiveFrom(context.Background(), "cid", 3)
	require.NoError(t, err)
	require.Equal(t, map[sharing.ID][]byte{3: []byte("unexpected")}, received)
}

func TestRouterConcurrentDisjointCorrelationIDs(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2, 3)
	router := network.NewRouter(delivery)
	defer router.Close()

	var group errgroup.Group
	group.Go(func() error {
		received, err := router.ReceiveFrom(context.Background(), "cid-a", 2)
		if err != nil {
			return err
		}
		require.Equal(t, map[sharing.ID][]byte{2: []byte("payload-a")}, received)
		return nil
	})
	group.Go(func() error {
		received, err := router.ReceiveFrom(context.Background(), "cid-b", 3)
		if err != nil {
			return err
		}
		require.Equal(t, map[sharing.ID][]byte{3: []byte("payload-b")}, received)
		return nil
	})

	delivery.deliver(t, 3, "cid-b", []byte("payload-b"))
	delivery.deliver(t, 2, "cid-a", []byte("payload-a"))

	require.NoError(t, group.Wait())
}

func TestRouterNamespacedViewsIsolate(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2)
	router := network.NewRouter(delivery)
	defer router.Close()

	viewA := router.Namespaced("a")
	viewB := router.Namespaced("b")

	delivery.deliver(t, 2, "a/cid", []byte("payload-a"))
	delivery.deliver(t, 2, "b/cid", []byte("payload-b"))

	received, err := viewA.ReceiveFrom(context.Background(), "cid", 2)
	require.NoError(t, err)
	require.Equal(t, map[sharing.ID][]byte{2: []byte("payload-a")}, received)

	received, err = viewB.ReceiveFrom(context.Background(), "cid", 2)
	require.NoError(t, err)
	require.Equal(t, map[sharing.ID][]byte{2: []byte("payload-b")}, received)
}

func TestRouterNamespacedSendPrefixesCorrelationID(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2)
	router := network.NewRouter(delivery)
	defer router.Close()

	nested := router.Namespaced("a").Namespaced("x")
	err := nested.SendTo(context.Background(), "cid", map[sharing.ID][]byte{2: []byte("payload")})
	require.NoError(t, err)

	sent := delivery.sentMessages()
	require.Len(t, sent, 1)
	require.Equal(t, sharing.ID(2), sent[0].to)
	decoded, err := serde.UnmarshalCBOR[wireMessage](sent[0].message)
	require.NoError(t, err)
	require.Equal(t, "a/x/cid", decoded.CorrelationID)
	require.Equal(t, []byte("payload"), decoded.Payload)
}

func TestRouterConflictingDuplicatePoisons(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2, 3)
	router := network.NewRouter(delivery)
	defer router.Close()

	delivery.deliver(t, 2, "cid", []byte("one"))
	delivery.deliver(t, 2, "cid", []byte("two"))
	delivery.deliver(t, 3, "cid", []byte("three"))

	_, err := router.ReceiveFrom(context.Background(), "cid", 2, 3)
	require.ErrorIs(t, err, network.ErrDuplicateMessage)
}

func TestRouterIdenticalDuplicateTolerated(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2, 3)
	router := network.NewRouter(delivery)
	defer router.Close()

	delivery.deliver(t, 2, "cid", []byte("one"))
	delivery.deliver(t, 2, "cid", []byte("one"))
	delivery.deliver(t, 3, "cid", []byte("three"))

	received, err := router.ReceiveFrom(context.Background(), "cid", 2, 3)
	require.NoError(t, err)
	require.Equal(t, map[sharing.ID][]byte{2: []byte("one"), 3: []byte("three")}, received)
}

func TestRouterCancelledReceiveKeepsBufferedMessages(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2, 3)
	router := network.NewRouter(delivery)
	defer router.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := router.ReceiveFrom(ctx, "cid", 2, 3)
		errCh <- err
	}()

	delivery.deliver(t, 2, "cid", []byte("kept"))
	cancel()
	require.ErrorIs(t, <-errCh, context.Canceled)

	received, err := router.ReceiveFrom(context.Background(), "cid", 2)
	require.NoError(t, err)
	require.Equal(t, map[sharing.ID][]byte{2: []byte("kept")}, received)
}

func TestRouterTransportErrorFailsAllReceives(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2, 3)
	router := network.NewRouter(delivery)
	defer router.Close()

	var group errgroup.Group
	for _, correlationID := range []string{"cid-a", "cid-b"} {
		group.Go(func() error {
			_, err := router.ReceiveFrom(context.Background(), correlationID, 2)
			if !errors.Is(err, errStubTransport) {
				return err
			}
			return nil
		})
	}

	delivery.failReceive(errStubTransport)
	require.NoError(t, group.Wait())

	_, err := router.ReceiveFrom(context.Background(), "cid-c", 2)
	require.ErrorIs(t, err, errStubTransport)
}

func TestRouterCloseFailsPendingAndFutureReceives(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2)
	router := network.NewRouter(delivery)

	errCh := make(chan error, 1)
	go func() {
		_, err := router.ReceiveFrom(context.Background(), "cid", 2)
		errCh <- err
	}()

	view := router.Namespaced("a")
	view.Close()
	require.ErrorIs(t, <-errCh, network.ErrRouterClosed)

	_, err := router.ReceiveFrom(context.Background(), "cid", 2)
	require.ErrorIs(t, err, network.ErrRouterClosed)

	router.Close()
}

func TestRouterRejectsConcurrentSameCorrelationID(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2)
	router := network.NewRouter(delivery)
	defer router.Close()

	type receiveResult struct {
		received map[sharing.ID][]byte
		err      error
	}
	resultCh := make(chan receiveResult, 1)
	go func() {
		for {
			received, err := router.ReceiveFrom(context.Background(), "cid", 2)
			if errors.Is(err, network.ErrInvalidArgument) {
				continue
			}
			resultCh <- receiveResult{received: received, err: err}
			return
		}
	}()

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Eventually(t, func() bool {
		_, err := router.ReceiveFrom(cancelledCtx, "cid", 2)
		return errors.Is(err, network.ErrInvalidArgument)
	}, 5*time.Second, time.Millisecond)

	delivery.deliver(t, 2, "cid", []byte("payload"))
	result := <-resultCh
	require.NoError(t, result.err)
	require.Equal(t, map[sharing.ID][]byte{2: []byte("payload")}, result.received)
}

func TestRouterDropsMessagesFromOutsideQuorum(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2)
	router := network.NewRouter(delivery)
	defer router.Close()

	delivery.deliver(t, 9, "cid", []byte("spoofed"))
	delivery.deliver(t, 2, "cid", []byte("real"))

	received, err := router.ReceiveFrom(context.Background(), "cid", 2)
	require.NoError(t, err)
	require.Equal(t, map[sharing.ID][]byte{2: []byte("real")}, received)
}

func TestRouterBufferCapLatchesFailure(t *testing.T) {
	t.Parallel()

	delivery := newStubDelivery(1, 2)
	router := network.NewRouter(delivery)
	defer router.Close()

	for i := range 10001 {
		delivery.deliver(t, 2, "junk-"+strconv.Itoa(i), nil)
	}

	_, err := router.ReceiveFrom(context.Background(), "wanted", 2)
	require.ErrorIs(t, err, network.ErrReceiveBufferFull)
}
