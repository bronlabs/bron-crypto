package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

type (
	DealerFunc[FE algebra.PrimeFieldElement[FE]]                                             = kw.DealerFunc[FE]
	VerificationMatrix[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] = mat.ModuleValuedMatrix[E, FE]
)

// Name is the canonical name of this secret sharing scheme.
const Name sharing.Name = "Feldman's Verifiable Secret Sharing Scheme"
