package randfischlin

import (
	"bytes"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

func isAllZeros(data []byte) bool {
	zeros := byte(0)
	for _, b := range data {
		zeros |= b
	}
	return zeros == 0
}

func hash(data ...[]byte) ([]byte, error) {
	result, err := hashing.HashPrefixedLength(randomOracle, data...)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash values")
	}

	return result[:LBytes], nil
}

func sample(existing [][]byte, length int, prng io.Reader) ([]byte, error) {
outer:
	for {
		ei := make([]byte, length)
		_, err := io.ReadFull(prng, ei[:TBytes])
		if err != nil {
			return nil, errs.NewRandomSample("cannot read from PRNG")
		}

		for _, e := range existing {
			if bytes.Equal(e, ei) {
				continue outer
			}
		}
		return ei, nil
	}
}
