package fkechacha20

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/thirdparty/golang/crypto/chacha20"
)

const (
	ChachaPRNGSecurityStrength = chacha20.KeySize // 256 bits
	// Name csprng.Name = "FKE_CHACHA_20"
)

// Prng uses a fast-erasure version of `chacha20` stream cipher as a Prng.
type Prng struct {
	chacha *chacha20.FastKeyErasureCipher
	seeded bool
}

// NewPrng generates a Fast-erasure PRNG using Chacha20 from a
// seed of 256 bits of length and an optional salt.
func NewPrng(seed, salt []byte) (csprng.CSPRNG, error) {
	chachaPrng := new(Prng)
	if err := chachaPrng.Reseed(seed, salt); err != nil {
		return nil, errs.WrapFailed(err, "Could not create ChachaPRNG")
	}
	return chachaPrng, nil
}

// New returns a new ChachaPRNG with the provided seed and salt.
func (*Prng) New(seed, salt []byte) (csprng.CSPRNG, error) {
	return NewPrng(seed, salt)
}

// Generate fills the buffer with pseudo-random bytes. This PRNG does not use
// the `salt` parameter other than in the instantiation.
func (c *Prng) Generate(buffer, salt []byte) error {
	if !c.seeded {
		return errs.NewRandomSample("ChachaPRNG not seeded")
	}
	c.chacha.XORKeyStream(buffer, buffer)
	return nil
}

// Read fills the buffer with pseudo-random bytes.
func (c *Prng) Read(buffer []byte) (n int, err error) {
	if err = c.Generate(buffer, nil); err != nil {
		return 0, errs.WrapFailed(err, "Could not Generate bytes on ChachaPRNG")
	}
	return len(buffer), nil
}

// Reseed refreshes the PRNG with the provided seed material. For ChachaPRNG, it is equivalent to `ResetState`.
func (c *Prng) Reseed(seed, salt []byte) (err error) {
	switch seedLen := len(seed); {
	case seedLen == 0:
		c.chacha = nil
		c.seeded = false
		return nil
	case seedLen < ChachaPRNGSecurityStrength:
		seed = bitstring.PadToRight(seed, ChachaPRNGSecurityStrength-len(seed))
		fallthrough
	default:
		switch saltLen := len(salt); {
		case saltLen == 0:
			salt = make([]byte, chacha20.NonceSize)
		case saltLen < chacha20.NonceSize:
			return errs.NewArgument("invalid chacha salt length (%d, should be >=%d)", len(salt), chacha20.NonceSize)
		case saltLen < chacha20.NonceSizeX:
			salt = salt[:chacha20.NonceSize]
		default:
			salt = salt[:chacha20.NonceSizeX]
		}
		c.chacha, err = chacha20.NewFastErasureCipher(seed, salt)
		if err != nil {
			return errs.WrapFailed(err, "Could not create ChachaPRNG")
		}
		c.seeded = true
		return nil
	}
}

// Seed re-initialises the prng.
func (c *Prng) Seed(seed, salt []byte) error {
	err := c.Reseed(seed, salt)
	if err != nil {
		return errs.WrapFailed(err, "Could not re-initialise ChachaPRNG")
	}
	return nil
}

func (*Prng) SecurityStrength() int {
	return ChachaPRNGSecurityStrength
}
