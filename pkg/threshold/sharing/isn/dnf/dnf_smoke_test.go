package dnf_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn/dnf"
)

func _[E algebra.GroupElement[E]]() {
	var (
		_ sharing.LinearShare[*dnf.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E], *additive.Share[E], E, algebra.Numeric, *sharing.ThresholdAccessStructure] = (*dnf.Share[E])(nil)
		_ sharing.LSSS[
			*dnf.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E],
			*additive.Share[E], E,
			*isn.Secret[E], E,
			*dnf.DealerOutput[E], algebra.Numeric, sharing.DNFAccessStructure, dnf.DealerFunc[E],
		] = (*dnf.Scheme[E])(nil)
	)
}
