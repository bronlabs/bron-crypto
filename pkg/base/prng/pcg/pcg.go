package pcg

import (
	"encoding/binary"
	mrand "math/rand/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
)

var _ prng.SeedablePRNG = (*seededReader)(nil)

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
	if len(seed) != 8 || len(salt) != 8 {
		return errs.NewValue("seed and salt must be 8 bytes each")
	}
	seedUint64 := binary.LittleEndian.Uint64(seed)
	saltUint64 := binary.LittleEndian.Uint64(salt)
	r.v.Seed(seedUint64, saltUint64)
	return nil
}

func (r *seededReader) New(seed, salt []byte) (prng.SeedablePRNG, error) {
	seedUint64 := binary.LittleEndian.Uint64(seed)
	saltUint64 := binary.LittleEndian.Uint64(salt)
	return New(seedUint64, saltUint64), nil
}
