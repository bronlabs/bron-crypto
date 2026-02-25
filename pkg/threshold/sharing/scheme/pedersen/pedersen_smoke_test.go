package pedersen_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/pedersen"
)

func _[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]]() {
	var (
		_ sharing.Share[*pedersen.Share[S]]             = (*pedersen.Share[S])(nil)
		_ sharing.LinearShare[*pedersen.Share[S], S, S] = (*pedersen.Share[S])(nil)

		_ sharing.ThresholdSSS[*pedersen.Share[S], *pedersen.Secret[S], *pedersen.DealerOutput[E, S]]                                                               = (*pedersen.Scheme[E, S])(nil)
		_ sharing.VSSS[*pedersen.Share[S], *pedersen.Secret[S], pedersen.VerificationVector[E, S], *pedersen.DealerOutput[E, S], *sharing.ThresholdAccessStructure] = (*pedersen.Scheme[E, S])(nil)
		_ sharing.LSSS[*pedersen.Share[S], S, *pedersen.Secret[S], S, *pedersen.DealerOutput[E, S], S, *sharing.ThresholdAccessStructure, *pedersen.DealerFunc[S]]  = (*pedersen.Scheme[E, S])(nil)
	)
}
