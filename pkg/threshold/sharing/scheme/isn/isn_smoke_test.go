package isn_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/isn"
)

func _[E algebra.GroupElement[E]]() {
	var (
		_ sharing.LinearShare[*isn.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E], algebra.Numeric] = (*isn.Share[E])(nil)
		_ sharing.LSSS[
			*isn.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E],
			*isn.Secret[E], E,
			*isn.DealerOutput[E], algebra.Numeric, accessstructures.Monotone, isn.DealerFunc[E],
		] = (*isn.Scheme[E])(nil)
	)
}
