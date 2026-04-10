package pcg

import (
	"encoding/binary"
	mrand "math/rand/v2"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/prng"
)

var (
	ErrInvalidSeedLength = errs.New("seed length is not 8 bytes")
	ErrInvalidSaltLength = errs.New("salt length is not 8 bytes")
)

type Pcg struct {
	v *mrand.PCG
}

// New creates a new PCG PRNG seeded with the given seed and salt.
func New(seed, salt uint64) *Pcg {
	return &Pcg{
		v: mrand.NewPCG(seed, salt),
	}
}

// NewRandomised creates a new PCG PRNG with random seed and salt.
func NewRandomised() *Pcg {
	return &Pcg{
		v: mrand.NewPCG(mrand.Uint64(), mrand.Uint64()), //nolint:gosec // weak prng is intentional.
	}
}

// Read fills the provided byte slice p with random bytes.
func (r *Pcg) Read(p []byte) (int, error) {
	n := len(p)
	for len(p) >= 8 {
		binary.LittleEndian.PutUint64(p[:8], r.v.Uint64())
		p = p[8:]
	}
	if len(p) > 0 {
		var tail [8]byte
		binary.LittleEndian.PutUint64(tail[:], r.v.Uint64())
		copy(p, tail[:len(p)])
	}
	return n, nil
}

// Seed resets the internal state of the PRNG with the provided seed and salt.
func (r *Pcg) Seed(seed, salt []byte) error {
	if err := r.validateSeedInputs(seed, salt); err != nil {
		return errs.Wrap(err).WithMessage("invalid inputs")
	}
	seedUint64 := binary.LittleEndian.Uint64(seed)
	saltUint64 := binary.LittleEndian.Uint64(salt)
	r.v.Seed(seedUint64, saltUint64)
	return nil
}

func (*Pcg) validateSeedInputs(seed, salt []byte) error {
	validationErrs := []error{}
	if len(seed) != 8 {
		validationErrs = append(validationErrs, ErrInvalidSeedLength)
	}
	if len(salt) != 8 {
		validationErrs = append(validationErrs, ErrInvalidSaltLength)
	}
	return errs.Join(validationErrs...)
}

// New generates a new PRNG of the same type with the provided seed and salt.
func (r *Pcg) New(seed, salt []byte) (prng.SeedablePRNG, error) {
	if err := r.validateSeedInputs(seed, salt); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid inputs")
	}
	seedUint64 := binary.LittleEndian.Uint64(seed)
	saltUint64 := binary.LittleEndian.Uint64(salt)
	return New(seedUint64, saltUint64), nil
}
