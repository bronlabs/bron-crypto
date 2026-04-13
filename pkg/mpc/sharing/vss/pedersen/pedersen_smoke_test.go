package pedersen_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/pedersen"
)

func _[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.VSSS[
			*pedersen.Share[FE], *kw.Secret[FE], *pedersen.VerificationVector[E, FE],
			*pedersen.DealerOutput[E, FE],
		] = (*pedersen.Scheme[E, FE])(nil)

		_ sharing.LSSS[
			*pedersen.Share[FE], []FE,
			*kw.Secret[FE], FE,
			*pedersen.DealerOutput[E, FE], *pedersen.DealerFunc[FE],
		] = (*pedersen.Scheme[E, FE])(nil)
	)
}
