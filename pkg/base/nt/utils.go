package nt

import (
	crand "crypto/rand"
	"io"
	"math/big"

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
		FromBig(*big.Int) (E, error)
	},
	E interface {
		algebra.HemiRingElement[E]
		*num.NatPlus | *num.Nat | *num.Uint
	},
](structure S, bitlen uint, prng io.Reader) (E, error) {
	if utils.IsNil(structure) || prng == nil {
		return *new(E), ErrIsNil.WithMessage("structure and prng must not be nil")
	}
	if bitlen == 0 {
		return *new(E), ErrInvalidArgument.WithMessage("bitlen must be at least 1")
	}
	if bitlen == 1 {
		// only exact-1-bit value is 1
		return structure.FromBig(big.NewInt(1))
	}
	half := new(big.Int).Lsh(big.NewInt(1), bitlen-1)
	q, err := crand.Int(prng, half) // [0, 2^(bitlen-1))
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to sample random element")
	}
	q.Add(q, half) // shift into [2^(bitlen-1), 2^bitlen)
	q.SetBit(q, int(bitlen-1), 1)
	out, err := structure.FromBig(q)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("failed to convert random big.Int to element")
	}
	return out, nil
}
