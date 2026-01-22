package fkechacha20

import (
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng"
	"github.com/bronlabs/bron-crypto/thirdparty/golang/crypto/chacha20"
)

// Prng uses a fast-erasure version of `chacha20` stream cipher as a Prng.
type Prng struct {
	chacha *chacha20.FastKeyErasureCipher
	seeded bool
}

// NewPrng generates a Fast-erasure PRNG using Chacha20 from a
// seed of 256 bits of length and an optional salt.
func NewPrng(seed, salt []byte) (*Prng, error) {
	chachaPrng := new(Prng)
	if err := chachaPrng.Reseed(seed, salt); err != nil {
		return nil, errs.Wrap(err).WithMessage("Could not create ChachaPRNG")
	}
	return chachaPrng, nil
}

// New returns a new ChachaPRNG with the provided seed and salt.
func (*Prng) New(seed, salt []byte) (csprng.SeedableCSPRNG, error) {
	return NewPrng(seed, salt)
}

// Generate fills the buffer with pseudo-random bytes. This PRNG does not use
// the `salt` parameter other than in the instantiation.
func (c *Prng) Generate(buffer, salt []byte) error {
	if !c.seeded {
		return ErrRandomSample.WithMessage("not seeded")
	}
	c.chacha.XORKeyStream(buffer, buffer)
	return nil
}

// Read fills the buffer with pseudo-random bytes.
func (c *Prng) Read(buffer []byte) (n int, err error) {
	if err = c.Generate(buffer, nil); err != nil {
		return 0, errs.Wrap(err).WithMessage("Could not Generate bytes on ChachaPRNG")
	}
	return len(buffer), nil
}

// Reseed refreshes the PRNG with the provided seed material. For ChachaPRNG, it is equivalent to `ResetState`.
func (c *Prng) Reseed(seed, salt []byte) (err error) {
	if len(seed) > chacha20.KeySize || len(salt) > chacha20.NonceSizeX {
		return ErrInvalidArgument.WithMessage("invalid chacha seed or salt length (%d, %d)", len(seed), len(salt))
	}

	var key [chacha20.KeySize]byte
	copy(key[:], seed)
	var nonce [chacha20.NonceSizeX]byte
	copy(nonce[:], salt)
	c.chacha, err = chacha20.NewFastErasureCipher(key[:], nonce[:])
	if err != nil {
		return errs.Wrap(err).WithMessage("Could not create ChachaPRNG")
	}
	c.seeded = true
	return nil
}

// Seed re-initialises the prng.
func (c *Prng) Seed(seed, salt []byte) error {
	err := c.Reseed(seed, salt)
	if err != nil {
		return errs.Wrap(err).WithMessage("Could not re-initialise ChachaPRNG")
	}
	return nil
}

func (*Prng) SecurityStrength() int {
	return chacha20.KeySize
}

var (
	ErrInvalidArgument = errs.New("ChachaPRNG invalid argument")
	ErrRandomSample    = errs.New("ChachaPRNG random sample error")
)
