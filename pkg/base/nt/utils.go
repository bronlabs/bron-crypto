package nt

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// Random samples a uniform element with exactly bitlen bits, i.e. uniformly from [2^(bitlen-1), 2^bitlen).
// The top bit is always set, so every sample has the requested bit length.
func Random[
	S interface {
		algebra.HemiRing[E]
		One() E
		Random(lowInclusive, highExclusive E, prng io.Reader) (E, error)
	},
	E interface {
		algebra.HemiRingElement[E]
		algebra.LeftBitwiseShiftable[E]
		*num.NatPlus | *num.Nat | *num.Uint
	},
](structure S, bitlen uint, prng io.Reader) (E, error) {
	if utils.IsNil(structure) || prng == nil {
		return *new(E), ErrIsNil.WithMessage("structure and prng must not be nil")
	}
	if bitlen == 0 {
		return *new(E), ErrInvalidArgument.WithMessage("bitlen must be at least 1")
	}
	one := structure.One()
	low := one.Lsh(bitlen - 1)
	high := one.Lsh(bitlen)
	out, err := structure.Random(low, high, prng)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to sample random element")
	}
	return out, nil
}
