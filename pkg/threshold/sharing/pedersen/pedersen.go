package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials2"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

const Name sharing.Name = "Pedersen Verifiable Secret Sharing Scheme"

type (
	DealerFunc[S algebra.PrimeFieldElement[S]]                                            = *polynomials2.DirectSumPolynomial[S]
	VerificationVector[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] = *polynomials2.ModuleValuedPolynomial[E, S]
	AccessStructure                                                                       = shamir.AccessStructure
)

var NewAccessStructure = shamir.NewAccessStructure

func _[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]]() {
	var (
		_ sharing.Share[*Share[S]]                                                   = (*Share[S])(nil)
		_ sharing.LinearShare[*Share[S], S, *additive.Share[S], S, *AccessStructure] = (*Share[S])(nil)
		_ sharing.LinearlyShareableSecret[*Secret[S], S]                             = (*Secret[S])(nil)

		_ sharing.ThresholdSSS[*Share[S], *Secret[S], *DealerOutput[E, S], *AccessStructure]                                  = (*Scheme[E, S])(nil)
		_ sharing.VSSS[*Share[S], *Secret[S], VerificationVector[E, S], *DealerOutput[E, S], *AccessStructure]                = (*Scheme[E, S])(nil)
		_ sharing.LSSS[*Share[S], S, *additive.Share[S], *Secret[S], S, *DealerOutput[E, S], *AccessStructure, DealerFunc[S]] = (*Scheme[E, S])(nil)
	)
}
