package binrep3

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type DealerOutput struct {
	shares map[sharing.ID]*Share
}

func (do *DealerOutput) Shares() ds.Map[sharing.ID, *Share] {
	return hashmap.NewImmutableComparableFromNativeLike(do.shares)
}
