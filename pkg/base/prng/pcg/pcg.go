package pcg

import (
	"encoding/binary"
	mrand "math/rand/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
)

var (
	ErrInvalidSeedLength = errs2.New("seed length is not 8 bytes")
	ErrInvalidSaltLength = errs2.New("salt length is not 8 bytes")
)

type seededReader struct {
	v *mrand.PCG
}

func New(seed, salt uint64) prng.SeedablePRNG {
	return &seededReader{v: mrand.NewPCG(seed, salt)}
}

func NewRandomised() prng.SeedablePRNG {
	return &seededReader{v: mrand.NewPCG(mrand.Uint64(), mrand.Uint64())}
}

func (r *seededReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r.v.Uint64())
	}
	return len(p), nil
}

func (r *seededReader) Seed(seed, salt []byte) error {
	if err := r.validateSeedInputs(seed, salt); err != nil {
		return errs2.AttachStackTrace(err)
	}
	seedUint64 := binary.LittleEndian.Uint64(seed)
	saltUint64 := binary.LittleEndian.Uint64(salt)
	r.v.Seed(seedUint64, saltUint64)
	return nil
}

func (r *seededReader) validateSeedInputs(seed, salt []byte) error {
	validationErrs := []error{}
	if len(seed) != 8 {
		validationErrs = append(validationErrs, ErrInvalidSeedLength)
	}
	if len(salt) != 8 {
		validationErrs = append(validationErrs, ErrInvalidSaltLength)
	}
	return errs2.Join(validationErrs...)
}

func (r *seededReader) New(seed, salt []byte) (prng.SeedablePRNG, error) {
	seedUint64 := binary.LittleEndian.Uint64(seed)
	saltUint64 := binary.LittleEndian.Uint64(salt)
	return New(seedUint64, saltUint64), nil
}
