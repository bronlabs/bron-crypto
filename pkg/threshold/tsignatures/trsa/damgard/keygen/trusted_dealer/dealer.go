package trusted_dealer

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/intshamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/damgard"
	"io"
)

func Deal(protocol types.ThresholdProtocol, sk *rsa.PrivateKey, prng io.Reader) (ds.Map[types.IdentityKey, *damgard.Shard], error) {
	dealer := intshamir.NewDealer(protocol.Threshold(), protocol.TotalParties())
	shares, err := dealer.Deal(sk.D, sk.N.Nat(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot deal shares")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	shards := hashmap.NewHashableHashMap[types.IdentityKey, *damgard.Shard]()
	for _, share := range shares {
		id, ok := sharingConfig.Get(share.Id)
		if !ok {
			return nil, errs.NewFailed("no such identity")
		}
		shards.Put(id, &damgard.Shard{
			N:  sk.N,
			E:  sk.E,
			Di: share.Value.Clone(),
		})
	}

	return shards, nil
}
