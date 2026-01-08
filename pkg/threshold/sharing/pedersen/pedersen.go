// Package pedersen implements Pedersen's verifiable secret sharing (VSS) scheme.
//
// Pedersen VSS extends Feldman VSS with information-theoretic hiding. The dealer
// uses two random polynomials: f(x) for the secret and r(x) for blinding. Each
// share consists of (f(i), r(i)). The verification vector contains Pedersen
// commitments C_j = g^{a_j}·h^{b_j} where a_j, b_j are coefficients of f and r.
//
// Shareholders verify their share (s_i, t_i) by checking that g^{s_i}·h^{t_i} equals
// the evaluation of the verification vector at their ID. Unlike Feldman, the secret
// remains hidden even to an unbounded adversary (information-theoretic hiding),
// assuming the discrete log relation between g and h is unknown.
package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// Name is the canonical name of this secret sharing scheme.
const Name sharing.Name = "Pedersen Verifiable Secret Sharing Scheme"

type (
	// VerificationVector is the public commitment to the dealing polynomials,
	// where each coefficient is a Pedersen commitment: V_j = g^{a_j}·h^{b_j}.
	VerificationVector[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] = *polynomials.ModuleValuedPolynomial[E, S]
)
