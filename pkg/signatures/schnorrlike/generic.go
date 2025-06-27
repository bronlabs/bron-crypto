package schnorrlike

import (
	"hash"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

func ComputeGenericNonceCommitment[GE GroupElement[GE, S], S Scalar[S]](group Group[GE, S], prng io.Reader) (GE, S, error) {
	if prng == nil {
		return *new(GE), *new(S), errs.NewIsNil("prng")
	}
	sf, ok := group.ScalarStructure().(ScalarField[S])
	if !ok {
		return *new(GE), *new(S), errs.NewType("group")
	}
	k, err := algebrautils.RandomNonIdentity(sf, prng)
	if err != nil {
		return *new(GE), *new(S), errs.WrapRandomSample(err, "scalar")
	}
	return group.ScalarBaseOp(k), k, nil
}

func ComputeGenericResponse[S Scalar[S]](privateKeyValue, nonce, challenge S, responseOperatorIsNegative bool) (S, error) {
	if utils.IsNil(privateKeyValue) {
		return *new(S), errs.NewIsNil("private key")
	}
	if utils.IsNil(nonce) {
		return *new(S), errs.NewIsNil("nonce")
	}
	if utils.IsNil(challenge) {
		return *new(S), errs.NewIsNil("challenge")
	}
	operand := challenge.Mul(privateKeyValue)
	if responseOperatorIsNegative {
		operand = operand.Neg()
	}
	return nonce.Add(operand), nil
}

func MakeGenericChallenge[S Scalar[S]](scalarField ScalarField[S], hashFunc func() hash.Hash, challengeElementsAreLittleEndian bool, xs ...[]byte) (S, error) {
	if scalarField == nil {
		return *new(S), errs.NewIsNil("scalar field")
	}
	for _, x := range xs {
		if x == nil {
			return *new(S), errs.NewIsNil("an input is nil")
		}
	}
	digest, err := hashing.Hash(hashFunc, xs...)
	if err != nil {
		return *new(S), errs.WrapHashing(err, "could not compute fiat shamir hash")
	}
	if challengeElementsAreLittleEndian {
		slices.Reverse(digest)
	}
	challenge, err := scalarField.FromWideBytes(digest)
	if err != nil {
		return *new(S), errs.WrapSerialisation(err, "could not compute fiat shamir challenge")
	}
	return challenge, nil
}
