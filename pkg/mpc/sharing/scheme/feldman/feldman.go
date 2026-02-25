package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
)

type (
	// DealerFunc is the polynomial used to generate shares (same as Shamir).
	DealerFunc[FE algebra.PrimeFieldElement[FE]] = shamir.DealerFunc[FE]
	// VerificationVector is the public commitment to the dealing polynomial,
	// where each coefficient is lifted to the exponent: V_j = g^{a_j}.
	VerificationVector[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] = *polynomials.ModuleValuedPolynomial[E, FE]
)

// Name is the canonical name of this secret sharing scheme.
const Name sharing.Name = "Feldman's Verifiable Secret Sharing Scheme"
