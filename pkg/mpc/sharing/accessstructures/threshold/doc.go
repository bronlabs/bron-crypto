// Package threshold implements (t,n) threshold access structures.
//
// In a threshold access structure, any subset of at least t shareholders
// (out of n total) is authorized to reconstruct the secret. This is the
// most common access structure, used by Shamir, Feldman, and Pedersen schemes.
//
// The MSP induction builds a Vandermonde matrix where each shareholder's
// evaluation point is their ID, producing an ideal MSP (one row per
// shareholder).
package threshold
