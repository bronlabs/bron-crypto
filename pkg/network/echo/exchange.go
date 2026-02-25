package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/errs-go/errs"
)

// ExchangeEchoBroadcast runs an echo broadcast: send, echo, and verify consistent payloads for selected parties.
func ExchangeEchoBroadcast[B any](rt *network.Router, correlationID string, quorum network.Quorum, message B) (network.RoundMessages[B], error) {
	r, err := NewEchoBroadcastRunner(rt.PartyID(), quorum, correlationID, message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create echo broadcast runner")
	}
	result, err := r.Run(rt)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to run echo broadcast")
	}

	output := make(map[sharing.ID]B)
	for id, m := range result.Iter() {
		output[id] = m
	}
	return hashmap.NewImmutableComparableFromNativeLike(output), nil
}
