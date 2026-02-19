// Package shamir implements Shamir's (t,n) threshold secret sharing scheme.
//
// In Shamir's scheme, a secret s is encoded as the constant term of a random
// polynomial f(x) of degree t-1. Each share is a point (i, f(i)) on the polynomial.
// Any t shares can reconstruct s via Lagrange interpolation, while t-1 or fewer
// shares reveal no information about s (information-theoretic security).
package shamir
