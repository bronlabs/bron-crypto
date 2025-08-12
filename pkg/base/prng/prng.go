package prng

import "io"

type PRNG io.Reader

type SeedablePRNG interface {
	PRNG
	// Reset the internal state of the PRNG.
	Seed(seed, salt []byte) error
	// Generate a new PRNG of the same type with the provided seed and salt.
	New(seed, salt []byte) (SeedablePRNG, error)
}

// CSPRNG is a cryptographically-secure Pseudo-Random Number Generator, following
// the API from NIST SP-800-90A rev.1 specification with some additional functions.
type CSPRNG interface {
	SeedablePRNG
	// Read pseudo-random bytes. Salts the read with `readSalt` if provided.
	Generate(buffer, readSalt []byte) error
	// Reseed the PRNG with a new seed and salt. It does not (forcibly) reset the state.
	Reseed(seed, salt []byte) error
	// Returns the security strength of the PRNG (in bytes).
	SecurityStrength() int
}
