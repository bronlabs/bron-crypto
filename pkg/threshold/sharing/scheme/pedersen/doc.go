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
