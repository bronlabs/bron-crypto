package csprng

import (
	"sync"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

// Provide a thread-safe version for PRNGs.
type ThreadSafePrng struct {
	prng CSPRNG
	mu   sync.Mutex
}

// NewThreadSafePrng returns a thread-safe version of the provided PRNG.
func NewThreadSafePrng(prng CSPRNG) (threadSafePrng CSPRNG) {
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
		return 0, errs.WrapFailed(err, "failed to read from thread-safe prng")
	}
	return n, nil
}

// Read pseudo-random bytes. Salts the read with `readSalt` if provided.
func (tsp *ThreadSafePrng) Generate(buffer, readSalt []byte) error {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	if err := tsp.prng.Generate(buffer, readSalt); err != nil {
		return errs.WrapFailed(err, "failed to generate from thread-safe prng")
	}
	return nil
}

// Reseed the PRNG with a new seed and salt. It does not reset the state.
func (tsp *ThreadSafePrng) Reseed(seed, salt []byte) error {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	if err := tsp.prng.Reseed(seed, salt); err != nil {
		return errs.WrapFailed(err, "failed to reseed thread-safe prng")
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
		return errs.WrapFailed(err, "failed to seed thread-safe prng")
	}
	return nil
}

// Generate a new PRNG with the provided seed and salt. Does not need locking, as only fixed values are used.
func (tsp *ThreadSafePrng) New(seed, salt []byte) (CSPRNG, error) {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	prng, err := tsp.prng.New(seed, salt)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create new thread-safe prng")
	}
	return NewThreadSafePrng(prng), nil
}
