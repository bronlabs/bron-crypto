// Package pedersen provides prime-order Pedersen commitments: C = g^m · h^r over
// a prime-order group whose generators g and h have an unknown discrete-log
// relation. The scheme is perfectly hiding and computationally binding under the
// discrete-log assumption, additively homomorphic, and supports re-randomisation.
// A TrapdoorKey holding lambda = log_g(h) can equivocate, which is useful in
// simulation-based proofs but breaks binding for its holder.
//
// See README.md for details.
package pedersen
