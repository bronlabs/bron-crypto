package hashing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"hash"
)

// Hash iteratively writes all the inputs to the given hash function and returns the result.
func Hash(h func() hash.Hash, xs ...[]byte) ([]byte, error) {
	H := h()
	for i, x := range xs {
		if _, err := H.Write(x); err != nil {
			return nil, errs.WrapFailed(err, "could not write to H for input %d", i)
		}
	}
	digest := H.Sum(nil)
	return digest, nil
}
