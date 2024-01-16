package utils

import (
	crand "crypto/rand"
	"io"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func IncrementNat(n *saferith.Nat) *saferith.Nat {
	return new(saferith.Nat).Add(n, new(saferith.Nat).SetUint64(1), n.AnnouncedLen()+1)
}

func DecrementNat(n *saferith.Nat) *saferith.Nat {
	return new(saferith.Nat).Sub(n, new(saferith.Nat).SetUint64(1), n.AnnouncedLen())
}

func NatFromBig(x *big.Int, m *saferith.Modulus) *saferith.Nat {
	xx := new(saferith.Nat).SetBytes(x.Bytes())
	if m == nil || m.Big().Int64() == 0 {
		return xx
	}
	return new(saferith.Nat).Mod(xx, m)
}

func NatFromBytes(x []byte, m *saferith.Modulus) *saferith.Nat {
	return new(saferith.Nat).Mod(
		new(saferith.Nat).SetBytes(x), m,
	)
}

func RandomNat(prng io.Reader, lowInclusive, highExclusive *saferith.Nat) (*saferith.Nat, error) {
	max := new(saferith.Nat).Sub(highExclusive, lowInclusive, highExclusive.AnnouncedLen())
	if max.Big().Cmp(big.NewInt(0)) == 0 {
		return nil, errs.NewInvalidArgument("max must be greater than zero")
	}
	randInt, err := crand.Int(prng, max.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	return new(saferith.Nat).Add(lowInclusive, new(saferith.Nat).SetBig(randInt, highExclusive.AnnouncedLen()), highExclusive.AnnouncedLen()), nil
}

func NatSetBit(value *saferith.Nat, bit int) (*saferith.Nat, error) {
	if bit < 0 {
		return nil, errs.NewInvalidArgument("bit must be non-negative")
	}
	return new(saferith.Nat).SetBig(new(big.Int).SetBit(value.Big(), bit, 1), value.AnnouncedLen()), nil
}
