package csprng

import (
	"sync"

	"github.com/bronlabs/errs-go/errs"
)

var ErrNil = errs.New("nil")

// ThreadSafePrng provides a thread-safe version for PRNGs.
type ThreadSafePrng struct {
	prng SeedableCSPRNG
	mu   sync.Mutex
}

// NewThreadSafePrng returns a thread-safe version of the provided PRNG.
func NewThreadSafePrng(prng SeedableCSPRNG) (SeedableCSPRNG, error) {
	if prng == nil {
		return nil, ErrNil
	}
	return &ThreadSafePrng{
		prng: prng,
		mu:   sync.Mutex{},
	}, nil
}

// Read pseudo-random bytes, to use like `crand.Read()`.
func (tsp *ThreadSafePrng) Read(p []byte) (n int, err error) {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	n, err = tsp.prng.Read(p)
	if err != nil {
		return 0, errs.Wrap(err).WithMessage("failed to read from prng")
	}
	return n, nil
}

// Generate reads pseudo-random bytes. Salts the read with `readSalt` if provided.
func (tsp *ThreadSafePrng) Generate(buffer, readSalt []byte) error {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	if err := tsp.prng.Generate(buffer, readSalt); err != nil {
		return errs.Wrap(err).WithMessage("failed to generate from prng")
	}
	return nil
}

// Reseed the PRNG with a new seed and salt. It does not reset the state.
func (tsp *ThreadSafePrng) Reseed(seed, salt []byte) error {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	if err := tsp.prng.Reseed(seed, salt); err != nil {
		return errs.Wrap(err).WithMessage("failed to reseed prng")
	}
	return nil
}

// SecurityStrength returns the security strength of the PRNG (in bytes).
func (tsp *ThreadSafePrng) SecurityStrength() int {
	return tsp.prng.SecurityStrength()
}

// Seed resets the internal state of the PRNG.
func (tsp *ThreadSafePrng) Seed(seed, salt []byte) error {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	if err := tsp.prng.Seed(seed, salt); err != nil {
		return errs.Wrap(err).WithMessage("failed to seed prng")
	}
	return nil
}

// New creates a new PRNG with the provided seed and salt.
func (tsp *ThreadSafePrng) New(seed, salt []byte) (SeedableCSPRNG, error) {
	tsp.mu.Lock()
	defer tsp.mu.Unlock()
	prng, err := tsp.prng.New(seed, salt)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to construct new prng")
	}
	return NewThreadSafePrng(prng)
}
