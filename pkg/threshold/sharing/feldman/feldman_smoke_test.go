package feldman_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

func _[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.LinearShare[*feldman.Share[FE], FE, *additive.Share[FE], FE, *sharing.ThresholdAccessStructure] = (*feldman.Share[FE])(nil)
		_ sharing.LinearlyShareableSecret[*feldman.Secret[FE], FE]                                                = (*feldman.Secret[FE])(nil)

		_ sharing.ThresholdSSS[*feldman.Share[FE], *feldman.Secret[FE], *feldman.DealerOutput[E, FE]]                                                                       = (*feldman.Scheme[E, FE])(nil)
		_ sharing.VSSS[*feldman.Share[FE], *feldman.Secret[FE], feldman.VerificationVector[E, FE], *feldman.DealerOutput[E, FE], *sharing.ThresholdAccessStructure]         = (*feldman.Scheme[E, FE])(nil)
		_ sharing.PolynomialLSSS[*feldman.Share[FE], FE, *additive.Share[FE], *feldman.Secret[FE], FE, *feldman.DealerOutput[E, FE], FE, *sharing.ThresholdAccessStructure] = (*feldman.Scheme[E, FE])(nil)
	)
}
