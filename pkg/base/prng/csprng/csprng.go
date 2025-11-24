package csprng

import (
	"io"
)

// SeedableCSPRNG is a cryptographically secure Pseudo-Random Number Generator, following
// the API from NIST SP-800-90A rev.1 specification with some additional functions.
type SeedableCSPRNG interface {
	io.Reader // Read pseudo-random bytes, to use like `crand.Read()`

	// Generate reads pseudo-random bytes. Salts the read with `readSalt` if provided.
	Generate(buffer, readSalt []byte) error

	// Reseed the PRNG with a new seed and salt. It does not (forcibly) reset the state.
	Reseed(seed, salt []byte) error

	// SecurityStrength returns the security strength of the PRNG (in bytes).
	SecurityStrength() int

	// Seed resets the internal state of the PRNG.
	Seed(seed, salt []byte) error

	// Generate a new PRNG of the same type with the provided seed and salt.
	New(seed, salt []byte) (SeedableCSPRNG, error)
}
