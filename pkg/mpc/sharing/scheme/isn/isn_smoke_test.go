package isn_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
)

func _[E algebra.GroupElement[E]]() {
	var (
		_ sharing.LinearShare[*isn.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E]] = (*isn.Share[E])(nil)
		_ sharing.LSSS[
			*isn.Share[E], ds.Map[bitset.ImmutableBitSet[sharing.ID], E],
			*isn.Secret[E], E,
			*isn.DealerOutput[E], *cnf.CNF, isn.DealerFunc[E],
		] = (*isn.Scheme[E])(nil)
	)
}
