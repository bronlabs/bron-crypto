// Package feldman implements Feldman's verifiable secret sharing (VSS) scheme.
//
// Feldman VSS extends Shamir's scheme with public verification. The dealer
// publishes commitments C_j = g^{a_j} for each coefficient a_j of the dealing
// polynomial. Shareholders can verify their share s_i by checking that
// g^{s_i} = ∏_j C_j^{i^j}.
//
// This provides computational hiding (secret is hidden under DLog assumption)
// but only computational binding (dealer can potentially equivocate).
package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
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
