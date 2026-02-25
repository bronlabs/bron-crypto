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
