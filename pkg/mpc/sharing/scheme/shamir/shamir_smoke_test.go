package shamir_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
)

func _[FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.DealerOutput[*shamir.Share[FE]]                     = (*shamir.DealerOutput[FE])(nil)
		_ sharing.LinearShare[*shamir.Share[FE], FE, algebra.Numeric] = (*shamir.Share[FE])(nil)

		_ sharing.ThresholdSSS[*shamir.Share[FE], *shamir.Secret[FE], *shamir.DealerOutput[FE]]                                                         = (*shamir.Scheme[FE])(nil)
		_ sharing.PolynomialLSSS[*shamir.Share[FE], FE, *shamir.Secret[FE], FE, *shamir.DealerOutput[FE], algebra.Numeric, *accessstructures.Threshold] = (*shamir.Scheme[FE])(nil)
	)
}
