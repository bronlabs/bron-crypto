package schnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"hash"
	"slices"
)

func MakeGenericSchnorrChallenge[FE fields.PrimeFieldElement[FE]](field fields.PrimeField[FE], hashFunc func() hash.Hash, xs ...[]byte) (FE, error) {
	for _, x := range xs {
		if x == nil {
			return *new(FE), errs.NewIsNil("an input is nil")
		}
	}

	// TODO: use hashing package
	h := hashFunc()
	_, _ = h.Write(slices.Concat(xs...))
	digest := h.Sum(nil)
	slices.Reverse(digest)
	challenge, err := field.FromWideBytes(digest)
	if err != nil {
		return *new(FE), err
	}

	return challenge, nil
}
