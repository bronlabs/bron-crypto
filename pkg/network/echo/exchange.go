package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

func ExchangeEchoBroadcastSimple[B any](rt *network.Router, correlationId string, message B) (map[sharing.ID]B, error) {
	result, err := RunEchoBroadcast(rt, rt.PartyId(), hashset.NewComparable(rt.Quorum()...).Freeze(), correlationId, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to run echo broadcast")
	}

	output := make(map[sharing.ID]B)
	for id, m := range result.Iter() {
		output[id] = m
	}
	return output, nil
}
