// Package fiatshamir implements the Fiat-Shamir transform for compiling interactive
// sigma protocols into non-interactive zero-knowledge proofs.
//
// The Fiat-Shamir transform replaces the verifier's random challenge with a hash
// of the transcript, making the protocol non-interactive. This is a simple and
// efficient approach that provides computational security.
//
// The transform requires that the underlying sigma protocol has soundness error
// at least 2^(-128) to ensure computational security of the resulting NIZK proof.
package fiatshamir
