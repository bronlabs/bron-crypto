package isn_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
)

func _[E algebra.ModuleElement[E, S], S algebra.RingElement[S]]() {
	var (
		_ sharing.LinearShare[*isn.Share[E], E] = (*isn.Share[E])(nil)
		_ sharing.LSSS[
			*isn.Share[E], E,
			*isn.Secret[E], E,
			*isn.DealerOutput[E], *accessstructures.CNF, isn.DealerFunc[E],
		] = (*isn.Scheme[E])(nil)

		_ sharing.LiftableLSSS[
			*isn.Share[S], S,
			*isn.Secret[S], S,
			*isn.DealerOutput[S], *accessstructures.CNF, isn.DealerFunc[S],
			*isn.LiftedShare[E], E, isn.LiftedDealerFunc[E, S],
			*isn.LiftedSecret[E, S], E,
		] = (*isn.LiftableScheme[E, S])(nil)
	)
}
