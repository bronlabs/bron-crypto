package network_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

type stubDelivery struct {
	partyID sharing.ID
	quorum  []sharing.ID
	queue   []queuedDelivery
}

type queuedDelivery struct {
	from    sharing.ID
	message []byte
}

func (d *stubDelivery) PartyID() sharing.ID {
	return d.partyID
}

func (d *stubDelivery) Quorum() []sharing.ID {
	return d.quorum
}

func (*stubDelivery) Send(context.Context, sharing.ID, []byte) error {
	return nil
}

func (d *stubDelivery) Receive(context.Context) (sharing.ID, []byte, error) {
	msg := d.queue[0]
	d.queue = d.queue[1:]
	return msg.from, msg.message, nil
}

func TestRouterReceiveFromFiltersUnexpectedSenders(t *testing.T) {
	t.Parallel()

	expected, err := serde.MarshalCBOR(&struct {
		CorrelationID string `cbor:"correlationID"`
		Payload       []byte `cbor:"payload"`
	}{
		CorrelationID: "cid",
		Payload:       []byte("expected"),
	})
	require.NoError(t, err)
	unexpected, err := serde.MarshalCBOR(&struct {
		CorrelationID string `cbor:"correlationID"`
		Payload       []byte `cbor:"payload"`
	}{
		CorrelationID: "cid",
		Payload:       []byte("unexpected"),
	})
	require.NoError(t, err)

	delivery := &stubDelivery{
		partyID: 1,
		quorum:  []sharing.ID{1, 2, 3},
		queue: []queuedDelivery{
			{from: 3, message: unexpected},
			{from: 2, message: expected},
		},
	}

	router := network.NewRouter(delivery)
	received, err := router.ReceiveFrom(context.Background(), "cid", 2)
	require.NoError(t, err)
	require.Equal(t, map[sharing.ID][]byte{2: []byte("expected")}, received)
}

func TestRouterReceiveFromRejectsOversizedFrameBeforeDecode(t *testing.T) {
	t.Parallel()

	delivery := &stubDelivery{
		partyID: 1,
		quorum:  []sharing.ID{1, 2},
		queue: []queuedDelivery{
			{from: 2, message: []byte("not-cbor")},
		},
	}

	router := network.NewRouterWithOptions(delivery, network.RouterOptions{MaxFrameBytes: 4})
	_, err := router.ReceiveFrom(context.Background(), "cid", 2)
	require.Error(t, err)
	require.ErrorIs(t, err, network.ErrFrameTooLarge)
}

func TestRouterReceiveFromRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	message := marshalRouterTestMessage(t, "cid", []byte("too large"))
	delivery := &stubDelivery{
		partyID: 1,
		quorum:  []sharing.ID{1, 2},
		queue: []queuedDelivery{
			{from: 2, message: message},
		},
	}

	router := network.NewRouterWithOptions(delivery, network.RouterOptions{MaxPayloadBytes: 4})
	_, err := router.ReceiveFrom(context.Background(), "cid", 2)
	require.Error(t, err)
	require.ErrorIs(t, err, network.ErrPayloadTooLarge)
}

func TestRouterReceiveFromRejectsOversizedCorrelationID(t *testing.T) {
	t.Parallel()

	message := marshalRouterTestMessage(t, "correlation-id", []byte("ok"))
	delivery := &stubDelivery{
		partyID: 1,
		quorum:  []sharing.ID{1, 2},
		queue: []queuedDelivery{
			{from: 2, message: message},
		},
	}

	router := network.NewRouterWithOptions(delivery, network.RouterOptions{MaxCorrelationIDBytes: 4})
	_, err := router.ReceiveFrom(context.Background(), "cid", 2)
	require.Error(t, err)
	require.ErrorIs(t, err, network.ErrCorrelationIDTooLarge)
}

func TestRouterReceiveFromCapsBufferedBytes(t *testing.T) {
	t.Parallel()

	first := marshalRouterTestMessage(t, "other", []byte("1234567"))
	second := marshalRouterTestMessage(t, "other", []byte("7654321"))
	delivery := &stubDelivery{
		partyID: 1,
		quorum:  []sharing.ID{1, 2, 3},
		queue: []queuedDelivery{
			{from: 3, message: first},
			{from: 3, message: second},
		},
	}

	router := network.NewRouterWithOptions(delivery, network.RouterOptions{MaxBufferedBytes: 16})
	_, err := router.ReceiveFrom(context.Background(), "cid", 2)
	require.Error(t, err)
	require.ErrorIs(t, err, network.ErrReceiveBufferFull)
}

func marshalRouterTestMessage(t *testing.T, correlationID string, payload []byte) []byte {
	t.Helper()

	message, err := serde.MarshalCBOR(&struct {
		CorrelationID string `cbor:"correlationID"`
		Payload       []byte `cbor:"payload"`
	}{
		CorrelationID: correlationID,
		Payload:       payload,
	})
	require.NoError(t, err)
	return message
}
