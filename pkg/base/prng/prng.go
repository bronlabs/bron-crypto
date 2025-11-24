package prng

import "io"

// PRNG represents a pseudo-random number generator.
type PRNG io.Reader // TODO: should this be incorporated?

// SeedablePRNG represents a seedable pseudo-random number generator.
type SeedablePRNG interface {
	PRNG
	// Reset the internal state of the PRNG.
	Seed(seed, salt []byte) error
	// Generate a new PRNG of the same type with the provided seed and salt.
	New(seed, salt []byte) (SeedablePRNG, error)
}
