package schnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"hash"
	"slices"
)

type ChallengeBytesEndianness bool

const LittleEndian ChallengeBytesEndianness = true
const BigEndian ChallengeBytesEndianness = false

func MakeGenericSchnorrChallenge[FE fields.PrimeFieldElement[FE]](scalarField fields.PrimeField[FE], hashFunc func() hash.Hash, endianness ChallengeBytesEndianness, xs ...[]byte) (FE, error) {
	for _, x := range xs {
		if x == nil {
			return *new(FE), errs.NewIsNil("an input is nil")
		}
	}

	// TODO: use hashing package
	h := hashFunc()
	_, _ = h.Write(slices.Concat(xs...))
	digest := h.Sum(nil)
	if endianness == LittleEndian {
		slices.Reverse(digest)
	}

	challenge, err := scalarField.FromWideBytes(digest)
	if err != nil {
		return *new(FE), err
	}

	return challenge, nil
}
