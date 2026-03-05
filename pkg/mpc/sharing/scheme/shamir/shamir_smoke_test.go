package shamir_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
)

func _[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.DealerOutput[*shamir.Share[FE]]    = (*shamir.DealerOutput[FE])(nil)
		_ sharing.LinearShare[*shamir.Share[FE], FE] = (*shamir.Share[FE])(nil)

		_ sharing.ThresholdSSS[*shamir.Share[FE], *shamir.Secret[FE], *shamir.DealerOutput[FE]] = (*shamir.Scheme[FE])(nil)
		_ sharing.LSSS[
			*shamir.Share[FE], FE, *shamir.Secret[FE], FE, *shamir.DealerOutput[FE], *accessstructures.Threshold, *shamir.DealerFunc[FE],
		] = (*shamir.Scheme[FE])(nil)
		_ sharing.LiftableLSSS[
			*shamir.Share[FE], FE, *shamir.Secret[FE], FE, *shamir.DealerOutput[FE], *accessstructures.Threshold, *shamir.DealerFunc[FE],
			*shamir.LiftedShare[E, FE], E, *shamir.LiftedDealerFunc[E, FE],
			*shamir.LiftedSecret[E, FE], E,
		] = (*shamir.LiftableScheme[E, FE])(nil)
	)
}
