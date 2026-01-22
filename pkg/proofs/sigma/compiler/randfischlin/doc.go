// Package randfischlin implements a randomised variant of Fischlin's transform
// for compiling interactive sigma protocols into non-interactive zero-knowledge proofs.
//
// This variant uses fixed parameters (Lambda=128, L=8, R=16) rather than computing
// them from the protocol's special soundness. Challenges are sampled randomly and
// searched until a hash-to-zero condition is met.
//
// The randomised approach can be more efficient than standard Fischlin for certain
// protocols while maintaining 128-bit computational security.
package randfischlin
