package shamir_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
)

func _[FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.DealerOutput[*shamir.Share[FE]]    = (*shamir.DealerOutput[FE])(nil)
		_ sharing.LinearShare[*shamir.Share[FE], FE] = (*shamir.Share[FE])(nil)

		_ sharing.LSSS[*shamir.Share[FE], FE, *shamir.Secret[FE], FE, *shamir.DealerOutput[FE], shamir.DealerFunc[FE]] = (*shamir.Scheme[FE])(nil)
	)
}
