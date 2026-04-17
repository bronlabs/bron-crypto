// Package elog implements Figure 23 of CGGMP21, "Dlog with ElGamal
// Commitments". Given a prime-order group G with generator g, an ElGamal
// public key X, a second independent generator h, and public values (L, M, Y),
// the protocol proves knowledge of (y, lambda) such that
//
//	L = g^lambda,  M = g^y * X^lambda,  Y = h^y.
//
// It is realized as the AND-composition of two Maurer sigma protocols:
// elcomop (opening of the ElGamal commitment (L, M) to plaintext g^y under
// nonce lambda) and Schnorr (discrete log of Y with respect to base h). The
// two sub-witnesses are bound together by the consistency check M' = g^y
// performed in NewWitness, where M' is the elcomop plaintext.
//
// See README.md for details.
package elog
