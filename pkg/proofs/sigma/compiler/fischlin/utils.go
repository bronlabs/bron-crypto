package fischlin

import (
	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

func isLess(l, r *saferith.Nat) bool {
	_, _, less := l.Cmp(r)
	return less != 0
}

func isAllZeros(data []byte) bool {
	zeros := byte(0)
	for _, b := range data {
		zeros |= b
	}
	return zeros == 0
}

func hash(data ...[]byte) ([]byte, error) {
	result, err := hashing.HashChain(sha3.New256, data...)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash values")
	}

	return result[:lBytes], nil
}
