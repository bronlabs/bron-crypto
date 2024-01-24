package randomisedFischlin

import (
	"bytes"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

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
		return nil, errs.WrapHashingFailed(err, "cannot hash values")
	}

	return result[:lBytes], nil
}

func sample(existing [][]byte, length int, prng io.Reader) ([]byte, error) {
outer:
	for {
		ei := make([]byte, length)
		_, err := io.ReadFull(prng, ei[:tBytes])
		if err != nil {
			return nil, errs.NewFailed("cannot read from PRNG")
		}

		for _, e := range existing {
			if bytes.Equal(e, ei) {
				continue outer
			}
		}
		return ei, nil
	}
}
