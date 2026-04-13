package feldman_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
)

func _[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.VSSS[
			*kw.Share[FE], *kw.Secret[FE], *feldman.VerificationVector[E, FE],
			*feldman.DealerOutput[E, FE],
		] = (*feldman.Scheme[E, FE])(nil)

		_ sharing.LSSS[
			*kw.Share[FE], []FE,
			*kw.Secret[FE], FE,
			*feldman.DealerOutput[E, FE], *kw.DealerFunc[FE],
		] = (*feldman.Scheme[E, FE])(nil)
	)
}
