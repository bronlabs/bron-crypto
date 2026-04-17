// Package elcomop implements a sigma protocol for proof of knowledge of an
// opening of an ElGamal commitment, using Maurer's unifying framework.
//
// Given a prime-order group G with generator g, an ElGamal public key X, and a
// commitment (Gamma, Delta) = (g^lambda, M * X^lambda), the protocol proves
// knowledge of the opening (M, lambda) in G x F_q.
//
// See README.md for details.
package elcomop
