package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Name is the canonical name of this secret sharing scheme.
const Name sharing.Name = "Pedersen Verifiable Secret Sharing Scheme"

type (
	VerificationVector[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] = mat.ModuleValuedColumnVector[E, S]
)
