// Package pcg provides a seedable PCG-based PRNG for tests and non-cryptographic randomness.
//
// Security warning: PCG is not cryptographically secure. Production code must
// use a CSPRNG or accept an explicit cryptographically secure io.Reader instead.
// CI blocks imports of this package outside tests, test utilities, and tools.
package pcg
