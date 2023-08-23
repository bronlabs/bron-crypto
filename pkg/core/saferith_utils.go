package core

import (
	crand "crypto/rand"
	"io"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

func RandomNat(prng io.Reader, lowInclusive, highExclusive *saferith.Nat) (*saferith.Nat, error) {
	max := new(saferith.Nat).Sub(highExclusive, lowInclusive, highExclusive.AnnouncedLen())
	randInt, err := crand.Int(prng, max.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	return new(saferith.Nat).Add(lowInclusive, new(saferith.Nat).SetBig(randInt, highExclusive.AnnouncedLen()), highExclusive.AnnouncedLen()), nil
}

func NatSetBit(value *saferith.Nat, bit int) *saferith.Nat {
	// no native implementation
	return new(saferith.Nat).SetBig(new(big.Int).SetBit(value.Big(), bit, 1), value.AnnouncedLen())
}
