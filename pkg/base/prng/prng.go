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
