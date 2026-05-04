package prng

import "io"

// SeedablePRNG represents a seedable pseudo-random number generator.
type SeedablePRNG interface {
	io.Reader
	// Reset the internal state of the PRNG.
	Seed(seed, salt []byte) error
	// Generate a new PRNG of the same type with the provided seed and salt.
	New(seed, salt []byte) (SeedablePRNG, error)
}

// PRNGFuncTypeErase converts a generic PRNG constructor to a non-generic one returning io.Reader.
// This is useful when interfacing with APIs that require func() io.Reader.
func PRNGFuncTypeErase[H io.Reader](prngFunc func() H) func() io.Reader {
	return func() io.Reader {
		return prngFunc()
	}
}
