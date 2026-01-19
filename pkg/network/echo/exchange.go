package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// ExchangeEchoBroadcastSimple runs an echo broadcast: send, echo, and verify consistent payloads for all parties.
func ExchangeEchoBroadcastSimple[B any](rt *network.Router, correlationID string, message B) (network.RoundMessages[B], error) {
	r, err := NewEchoBroadcastRunner(rt.PartyID(), hashset.NewComparable(rt.Quorum()...).Freeze(), correlationID, message)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create echo broadcast runner")
	}
	result, err := r.Run(rt)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to run echo broadcast")
	}

	output := make(map[sharing.ID]B)
	for id, m := range result.Iter() {
		output[id] = m
	}
	return hashmap.NewImmutableComparableFromNativeLike(output), nil
}
