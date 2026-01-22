// Package sigand implements AND composition of sigma protocols.
//
// AND composition allows a prover to demonstrate knowledge of valid witnesses
// for ALL statements simultaneously. Unlike OR composition, the prover must
// know witnesses for every statement in the composition.
//
// The verifier sends a single challenge, and the same challenge is used for
// all sub-protocols. This ensures the prover cannot selectively respond to
// different challenges for different statements.
//
// The package provides two composition variants:
//   - Compose: n-way composition using the same protocol type for all statements
//   - CartesianCompose: binary composition allowing different protocol types
package sigand
