package isn_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/isn"
)

func _[E algebra.GroupElement[E]]() {
	var (
		_ sharing.LinearShare[*isn.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E], *additive.Share[E], E, algebra.Numeric, *sharing.ThresholdAccessStructure] = (*isn.Share[E])(nil)
		_ sharing.LSSS[
			*isn.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E],
			*additive.Share[E], E,
			*isn.Secret[E], E,
			*isn.DealerOutput[E], algebra.Numeric, sharing.CNFAccessStructure, isn.DealerFunc[E],
		] = (*isn.Scheme[E])(nil)
	)
}
