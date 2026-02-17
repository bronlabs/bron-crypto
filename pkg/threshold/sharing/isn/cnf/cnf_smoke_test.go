package cnf_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn/cnf"
)

func _[E algebra.GroupElement[E]]() {
	var (
		_ sharing.LinearShare[*cnf.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E], *additive.Share[E], E, algebra.Numeric, *sharing.ThresholdAccessStructure] = (*cnf.Share[E])(nil)
		_ sharing.LSSS[
			*cnf.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E],
			*additive.Share[E], E,
			*isn.Secret[E], E,
			*cnf.DealerOutput[E], algebra.Numeric, sharing.CNFAccessStructure, cnf.DealerFunc[E],
		] = (*cnf.Scheme[E])(nil)
	)
}
