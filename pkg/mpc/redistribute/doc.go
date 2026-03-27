// Package redistribute provides a two-round protocol for verifiable share
// redistribution between a qualified set of existing holders and a new linear
// access structure.
//
// Recoverers redistribute their current shares as verified subshares, and
// recoverees aggregate those subshares into fresh shares of the same secret.
// The protocol follows the verifiable redistribution approach of Wong and Wing,
// adapted to the Feldman-style verification and MSP-based sharing abstractions
// used in this repository.
//
// See README.md for details.
package redistribute
