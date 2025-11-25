package csprng

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

var (
	ErrConstructionFailed = errs2.New("failed to construct new prng")
	ErrReadFailed         = errs2.New("failed to read from prng")
	ErrGenerateFailed     = errs2.New("failed to generate from prng")
	ErrSeedFailed         = errs2.New("failed to seed prng")
	ErrReseedFailed       = errs2.New("failed to reseed prng")
)

// Provide a thread-safe version for PRNGs.
type ThreadSafePrng struct {
	prng SeedableCSPRNG
	mu   sync.Mutex
}

// NewThreadSafePrng returns a thread-safe version of the provided PRNG.
func NewThreadSafePrng(prng SeedableCSPRNG) (threadSafePrng SeedableCSPRNG) {
	return &ThreadSafePrng{
		prng: prng,
		mu:   sync.Mutex{},
	}
}

// Read pseudo-random bytes, to use like `crand.Read()`.
func (tsp *ThreadSafePrng) Read(p []byte) (n int, err error) {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	n, err = tsp.prng.Read(p)
	if err != nil {
		return 0, ErrReadFailed.WithStackFrame()
	}
	return n, nil
}

// Read pseudo-random bytes. Salts the read with `readSalt` if provided.
func (tsp *ThreadSafePrng) Generate(buffer, readSalt []byte) error {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	if err := tsp.prng.Generate(buffer, readSalt); err != nil {
		return ErrGenerateFailed.WithStackFrame()
	}
	return nil
}

// Reseed the PRNG with a new seed and salt. It does not reset the state.
func (tsp *ThreadSafePrng) Reseed(seed, salt []byte) error {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	if err := tsp.prng.Reseed(seed, salt); err != nil {
		return ErrReseedFailed.WithStackFrame()
	}
	return nil
}

// Returns the security strength of the PRNG (in bytes).
func (tsp *ThreadSafePrng) SecurityStrength() int {
	return tsp.prng.SecurityStrength()
}

// Reset the internal state of the PRNG.
func (tsp *ThreadSafePrng) Seed(seed, salt []byte) error {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	if err := tsp.prng.Seed(seed, salt); err != nil {
		return ErrSeedFailed.WithStackFrame()
	}
	return nil
}

// Generate a new PRNG with the provided seed and salt. Does not need locking, as only fixed values are used.
func (tsp *ThreadSafePrng) New(seed, salt []byte) (SeedableCSPRNG, error) {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	prng, err := tsp.prng.New(seed, salt)
	if err != nil {
		return nil, ErrConstructionFailed.WithStackFrame()
	}
	return NewThreadSafePrng(prng), nil
}
