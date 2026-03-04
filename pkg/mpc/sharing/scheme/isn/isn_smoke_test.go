package isn_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
)

func _[E algebra.GroupElement[E]]() {
	var (
		_ sharing.LinearShare[*isn.Share[E], E, algebra.Numeric] = (*isn.Share[E])(nil)
		_ sharing.LSSS[
			*isn.Share[E], E,
			*isn.Secret[E], E,
			*isn.DealerOutput[E], algebra.Numeric, accessstructures.Monotone, isn.DealerFunc[E],
		] = (*isn.Scheme[E])(nil)
	)
}
