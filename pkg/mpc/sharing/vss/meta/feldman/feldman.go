package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

type (
	// DealerFunc holds the dealer's secret state after dealing: the random
	// column vector r and the share vector λ = M · r. It is an alias for
	// kw.DealerFunc.
	DealerFunc[FE algebra.PrimeFieldElement[FE]] = kw.DealerFunc[FE]

	// VerificationVector is the public commitment V = [r]G, a module-valued
	// column matrix whose entries are the group-element lifts of the random
	// column: V_j = [r_j]G for j = 0, …, D−1. It is an alias for
	// mat.ModuleValuedMatrix.
	VerificationVector[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] = mat.ModuleValuedColumnVector[E, FE]
)

// Name is the canonical name of this secret sharing scheme.
const Name sharing.Name = "Feldman's Verifiable Secret Sharing Scheme"
