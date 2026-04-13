package trusteddealer

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
)

var (
	ErrIsNil = errs.New("is nil")
)

func Deal[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[G, S], accessStructure accessstructures.Monotone, prng io.Reader) (ds.Map[sharing.ID, *mpc.BaseShard[G, S]], error) {
	if group == nil || accessStructure == nil {
		return nil, ErrIsNil.WithMessage("argument")
	}

	scheme, err := feldman.NewScheme(group, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Feldman scheme")
	}
	dealOutput, _, err := scheme.DealRandom(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot deal Feldman shares")
	}

	shards := hashmap.NewComparable[sharing.ID, *mpc.BaseShard[G, S]]()
	for id, share := range dealOutput.Shares().Iter() {
		shard, err := mpc.NewBaseShard(share, dealOutput.VerificationMaterial(), scheme.MSP())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create base shard")
		}
		shards.Put(id, shard)
	}
	return shards.Freeze(), nil
}
