package schnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"hash"
	"slices"
)

func MakeGenericSchnorrChallenge[S fields.PrimeFieldElement[S]](hashFunc func() hash.Hash, xs ...[]byte) (S, error) {
	for _, x := range xs {
		if x == nil {
			return *new(S), errs.NewIsNil("an input is nil")
		}
	}

	// TODO: use hashing package
	h := hashFunc()
	digest := h.Sum(slices.Concat(xs...))

	// TODO(aalireza): add methods on curve to return scalar field
	scalarField, err := fields.GetPrimeField[S](*new(S))
	if err != nil {
		return *new(S), err
	}
	challenge, err := scalarField.FromWideBytes(digest)
	if err != nil {
		return *new(S), err
	}

	return challenge, nil
}
