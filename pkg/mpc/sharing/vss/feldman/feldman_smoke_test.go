package feldman_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
)

func _[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.LinearShare[*feldman.Share[FE], FE] = (*feldman.Share[FE])(nil)

		_ sharing.VSSS[*feldman.Share[FE], *feldman.Secret[FE], feldman.VerificationVector[E, FE], *feldman.DealerOutput[E, FE]] = (*feldman.Scheme[E, FE])(nil)
		_ sharing.LSSS[*feldman.Share[FE], FE, *feldman.Secret[FE], FE, *feldman.DealerOutput[E, FE], feldman.DealerFunc[FE]]    = (*feldman.Scheme[E, FE])(nil)
	)
}
