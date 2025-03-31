package saferith_utils

import (
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
	"io"
)

var (
	NatZero = new(saferith.Nat)
	NatOne  = new(saferith.Nat).SetUint64(1).Resize(1)

	IntZero = new(saferith.Int)
	IntOne  = new(saferith.Int).SetUint64(1).Resize(1)
)

func NatRandom(prng io.Reader, lowInclusive, highExclusive *saferith.Nat) (*saferith.Nat, error) {
	natRange := new(saferith.Nat).Sub(highExclusive, lowInclusive, highExclusive.AnnouncedLen())
	if natRange.EqZero() == 1 {
		return nil, errs.NewArgument("max must be greater than zero")
	}

	randInt, err := crand.Int(prng, natRange.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	return new(saferith.Nat).Add(lowInclusive, new(saferith.Nat).SetBig(randInt, highExclusive.AnnouncedLen()), highExclusive.AnnouncedLen()), nil
}

func IntRandom(prng io.Reader, lowInclusive, highExclusive *saferith.Int) (*saferith.Int, error) {
	intRange := new(saferith.Int).Add(highExclusive, lowInclusive.Clone().Neg(1), -1)
	if intRange.IsNegative() != 0 || lowInclusive.Eq(highExclusive) != 0 {
		return nil, errs.NewArgument("max must be greater than zero")
	}

	randBi, err := crand.Int(prng, intRange.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	return new(saferith.Int).Add(lowInclusive, new(saferith.Int).SetBig(randBi, randBi.BitLen()), -1), nil
}
