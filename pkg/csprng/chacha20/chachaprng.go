package chacha20

import (
	"golang.org/x/crypto/chacha20"

	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/csprng"
)

const ChachaPRNGSecurityStrength = chacha20.KeySize // 256 bits

/*.-------------------------- Chacha20 as PRNG ------------------------------.*/

// ChachaPRNG uses `chacha20` stream cipher as a PRNG.
type ChachaPRNG struct {
	chacha *chacha20.Cipher
	seeded bool
}

// NewChachaPRNG generates a NewChachaPRNG form a seed of 256 bits of length
// and an optional salt (e.g., the sessionID).
func NewChachaPRNG(seed, salt []byte) (csprng.CSPRNG, error) {
	chachaPrng := new(ChachaPRNG)
	if err := chachaPrng.Reseed(seed, salt); err != nil {
		return nil, errs.WrapFailed(err, "Could not create ChachaPRNG")
	}
	return chachaPrng, nil
}

// New returns a new ChachaPRNG with the provided seed and salt.
func (*ChachaPRNG) New(seed, salt []byte) (csprng.CSPRNG, error) {
	return NewChachaPRNG(seed, salt)
}

// Generate fills the buffer with pseudo-random bytes. This PRNG does not use
// the `salt` parameter other than in the instantiation.
func (c *ChachaPRNG) Generate(buffer, salt []byte) error {
	if !c.seeded {
		return errs.NewRandomSampleFailed("ChachaPRNG not seeded")
	}
	c.chacha.XORKeyStream(buffer, make([]byte, len(buffer)))
	return nil
}

// Read fills the buffer with pseudo-random bytes.
func (c *ChachaPRNG) Read(buffer []byte) (n int, err error) {
	if err = c.Generate(buffer, nil); err != nil {
		return 0, errs.WrapFailed(err, "Could not Generate bytes on ChachaPRNG")
	}
	return len(buffer), nil
}

// Reseed refreshes the PRNG with the provided seed material. For ChachaPRNG, it is equivalent to `ResetState`.
func (c *ChachaPRNG) Reseed(seed, salt []byte) (err error) {
	switch seedLen := len(seed); {
	case seedLen == 0:
		c.chacha = nil
		c.seeded = false
		return nil
	case seedLen < ChachaPRNGSecurityStrength:
		return errs.NewInvalidArgument("invalid chacha seed length (%d, should be >=%d)", len(seed), ChachaPRNGSecurityStrength)
	default:
		switch saltLen := len(salt); {
		case saltLen == 0:
			salt = make([]byte, chacha20.NonceSize)
		case saltLen < chacha20.NonceSize:
			return errs.NewInvalidArgument("invalid chacha salt length (%d, should be >=%d)", len(salt), chacha20.NonceSize)
		case saltLen < chacha20.NonceSizeX:
			salt = salt[:chacha20.NonceSize]
		default:
			salt = salt[:chacha20.NonceSizeX]
		}
		c.chacha, err = chacha20.NewUnauthenticatedCipher(seed, salt)
		if err != nil {
			return errs.WrapFailed(err, "Could not create Chacha stream cipher")
		}
		c.seeded = true
		return nil
	}
}

// Seed re-initialises the prng.
func (c *ChachaPRNG) Seed(seed, salt []byte) error {
	err := c.Reseed(seed, salt)
	if err != nil {
		return errs.WrapFailed(err, "Could not re-initialise ChachaPRNG")
	}
	return nil
}

func (*ChachaPRNG) SecurityStrength() int {
	return ChachaPRNGSecurityStrength
}
