//go:build !purego && !nobignum

package boring

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

func NatToBigNum(nat *saferith.Nat) (*BigNum, error) {
	natBytes := nat.Bytes()
	bn, err := NewBigNum().SetBytes(natBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set BigNum bytes")
	}

	return bn, nil
}

func BigNumToNat(bn *BigNum) (*saferith.Nat, error) {
	bnBytes, err := bn.Bytes()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get BigNum bytes")
	}

	nat := new(saferith.Nat).SetBytes(bnBytes)
	return nat, nil
}
