package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials2"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

type (
	DealerFunc[FE algebra.PrimeFieldElement[FE]]                                             = shamir.DealerFunc[FE]
	VerificationVector[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] = *polynomials2.ModuleValuedPolynomial[E, FE]
	AccessStructure                                                                          = shamir.AccessStructure
)

const Name sharing.Name = "Feldman's Verifiable Secret Sharing Scheme"

var (
	NewAccessStructure = shamir.NewAccessStructure
)

func _[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.LinearShare[*Share[FE], FE, *additive.Share[FE], FE, *AccessStructure] = (*Share[FE])(nil)
		_ sharing.LinearlyShareableSecret[*Secret[FE], FE]                               = (*Secret[FE])(nil)

		_ sharing.ThresholdSSS[*Share[FE], *Secret[FE], *DealerOutput[E, FE], *AccessStructure]                                = (*Scheme[E, FE])(nil)
		_ sharing.VSSS[*Share[FE], *Secret[FE], VerificationVector[E, FE], *DealerOutput[E, FE], *AccessStructure]             = (*Scheme[E, FE])(nil)
		_ sharing.PolynomialLSSS[*Share[FE], FE, *additive.Share[FE], *Secret[FE], FE, *DealerOutput[E, FE], *AccessStructure] = (*Scheme[E, FE])(nil)
	)
}
