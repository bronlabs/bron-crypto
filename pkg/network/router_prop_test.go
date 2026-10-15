package network_test

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

func TestRouterDemuxProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		numSenders := rapid.IntRange(1, 3).Draw(rt, "numSenders")
		numCorrelationIDs := rapid.IntRange(1, 6).Draw(rt, "numCorrelationIDs")

		quorum := []sharing.ID{1}
		for s := range numSenders {
			quorum = append(quorum, sharing.ID(s+2))
		}

		type entry struct {
			correlationID string
			from          sharing.ID
			payload       []byte
			order         int
		}
		var entries []entry
		want := make(map[string]map[sharing.ID][]byte)
		for c := range numCorrelationIDs {
			correlationID := "cid-" + strconv.Itoa(c)
			want[correlationID] = make(map[sharing.ID][]byte)
			for _, from := range quorum[1:] {
				payload := rapid.SliceOfN(rapid.Byte(), 1, 16).Draw(rt, "payload")
				order := rapid.Int().Draw(rt, "order")
				entries = append(entries, entry{correlationID: correlationID, from: from, payload: payload, order: order})
				want[correlationID][from] = payload
			}
		}
		slices.SortStableFunc(entries, func(a, b entry) int { return cmp.Compare(a.order, b.order) })

		delivery := newStubDelivery(quorum...)
		router := network.NewRouter(delivery)
		defer router.Close()

		var group errgroup.Group
		results := make([]map[sharing.ID][]byte, numCorrelationIDs)
		for c := range numCorrelationIDs {
			group.Go(func() error {
				received, err := router.ReceiveFrom(context.Background(), "cid-"+strconv.Itoa(c), quorum[1:]...)
				results[c] = received
				return err
			})
		}
		for _, e := range entries {
			delivery.deliver(rt, e.from, e.correlationID, e.payload)
		}

		require.NoError(rt, group.Wait())
		for c := range numCorrelationIDs {
			require.Equal(rt, want["cid-"+strconv.Itoa(c)], results[c])
		}
	})
}
