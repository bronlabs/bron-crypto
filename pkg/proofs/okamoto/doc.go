// Package okamoto implements Okamoto's proof of knowledge of a representation.
// Given generators h_1, ..., h_m of a prime-order group and a public element z,
// it proves knowledge of exponents (x_1, ..., x_m) such that
// z = h_1^{x_1} * ... * h_m^{x_m}, using Maurer's unifying framework.
//
// When m = 2 with Pedersen generators (g, h), this reduces to a proof of knowledge
// of opening of a Pedersen commitment C = g^m * h^r.
//
// See README.md for details.
package okamoto
