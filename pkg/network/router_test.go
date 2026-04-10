package network_test

import (
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

func (*stubDelivery) Send(sharing.ID, []byte) error {
	return nil
}

func (d *stubDelivery) Receive() (sharing.ID, []byte, error) {
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
	received, err := router.ReceiveFrom("cid", 2)
	require.NoError(t, err)
	require.Equal(t, map[sharing.ID][]byte{2: []byte("expected")}, received)
}
