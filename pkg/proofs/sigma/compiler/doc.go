// Package compiler provides compilers that transform interactive sigma protocols
// into non-interactive zero-knowledge proofs of knowledge (NIZKPoK).
//
// This package supports three compiler implementations:
//   - Fiat-Shamir: A simple, efficient compiler using hash-based challenge derivation
//   - Fischlin: A UC-secure compiler using repeated attempts with hash-based filtering
//   - Randomised Fischlin: A variant of Fischlin using randomised attempts with hash-based filtering, usable for OR composition.
//
// Each compiler takes an interactive sigma protocol and produces a non-interactive
// protocol that can generate and verify proofs without interaction between parties.
package compiler
