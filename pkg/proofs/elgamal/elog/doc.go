// Package elog implements Figure 23 of CGGMP21, "Dlog with ElGamal
// Commitments". Given a prime-order group G with generator g, an ElGamal
// public key X, a second base h, and public values (L, M, Y), the protocol
// proves knowledge of (y, lambda) such that
//
//	L = g^lambda,  M = g^y * X^lambda,  Y = h^y.
//
// It is realised as a single Maurer sigma protocol whose one-way homomorphism
// maps the witness (y, lambda) in F_q x F_q to the statement
// (g^lambda, g^y * X^lambda, h^y) in G x G x G. The binding between the value
// committed in (L, M) and the discrete logarithm of Y is therefore part of
// what the verifier checks, rather than a property of honest witness
// construction.
//
// See README.md for details.
package elog
