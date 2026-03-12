// Package feldman implements Feldman's verifiable secret sharing (VSS) scheme
// generalised to arbitrary linear access structures via Karchmer-Wigderson
// monotone span programmes (MSPs).
//
// Classical Feldman VSS is defined over Shamir's polynomial-based scheme and
// is therefore restricted to (t, n) threshold access structures. This package
// replaces Shamir with the KW MSP-based LSSS, lifting Feldman verification to
// any monotone access structure that admits an MSP — including threshold,
// unanimity, CNF, hierarchical conjunctive, and boolean-expression structures.
//
// # Dealing
//
// The dealer samples a random column vector r ∈ F^D (with r[0] = secret) and
// computes the share vector λ = M · r, where M is the MSP matrix (n × D).
// Each shareholder i receives the entries of λ corresponding to their MSP rows.
// The dealer publishes the verification vector V = [r]G, a D × 1 column of
// group elements.
//
// # Verification
//
// Given V and the public MSP, any party can verify the share of shareholder i
// by computing the expected lifted share via the left module action:
//
//	M_i · V = [M_i · r]G = [λ_i]G
//
// and comparing it against the manually lifted scalar share [λ_i]G. This is
// the direct generalisation of the classical Feldman check ∏ V_j^{x^j} =
// g^{f(x)}, which is itself the left module action of a Vandermonde row on V.
//
// # Security
//
// The scheme provides computational hiding (secret is hidden under the discrete
// logarithm assumption) and public verifiability (any party can check shares
// given the verification vector). Like classical Feldman, it does not provide
// information-theoretic binding: a malicious dealer can potentially equivocate.
// For unconditional binding, see Pedersen VSS.
package feldman
