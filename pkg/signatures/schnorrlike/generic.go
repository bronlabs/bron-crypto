package schnorrlike

import (
	"hash"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

// ComputeGenericNonceCommitment generates a random nonce k and commitment R = k·G.
// This is used by Schnorr variants that don't have deterministic nonce generation.
//
// The shouldNegateNonce callback allows variants to enforce parity constraints.
// For example, BIP-340 requires R to have an even y-coordinate, so if R.y is odd,
// the nonce k is negated to flip the parity of R.
//
// Returns the nonce commitment R and the nonce scalar k.
func ComputeGenericNonceCommitment[GE GroupElement[GE, S], S Scalar[S]](
	group Group[GE, S], prng io.Reader, shouldNegateNonce func(nonceCommitment GE) bool,
) (R GE, k S, err error) {
	if prng == nil {
		return *new(GE), *new(S), ErrInvalidArgument.WithMessage("prng is nil")
	}
	sf, ok := group.ScalarStructure().(ScalarField[S])
	if !ok {
		return *new(GE), *new(S), ErrInvalidArgument.WithMessage("group type assertion failed")
	}
	k, err = algebrautils.RandomNonIdentity(sf, prng)
	if err != nil {
		return *new(GE), *new(S), errs.Wrap(err).WithMessage("scalar")
	}
	if shouldNegateNonce != nil && shouldNegateNonce(group.ScalarBaseOp(k)) {
		k = k.Neg()
	}
	R = group.ScalarBaseOp(k)
	return R, k, nil
}

// ComputeGenericResponse computes the Schnorr response scalar s = k ± e·x.
//
// The response equation is:
//   - s = k + e·x when responseOperatorIsNegative is false (standard)
//   - s = k - e·x when responseOperatorIsNegative is true
//
// Parameters:
//   - privateKeyValue: the private key scalar x
//   - nonce: the ephemeral nonce scalar k
//   - challenge: the Fiat-Shamir challenge e
//   - responseOperatorIsNegative: if true, subtracts e·x instead of adding
func ComputeGenericResponse[S Scalar[S]](privateKeyValue, nonce, challenge S, responseOperatorIsNegative bool) (S, error) {
	if utils.IsNil(privateKeyValue) {
		return *new(S), ErrInvalidArgument.WithMessage("private key is nil")
	}
	if utils.IsNil(nonce) {
		return *new(S), ErrInvalidArgument.WithMessage("nonce is nil")
	}
	if utils.IsNil(challenge) {
		return *new(S), ErrInvalidArgument.WithMessage("challenge is nil")
	}
	operand := challenge.Mul(privateKeyValue)
	if responseOperatorIsNegative {
		operand = operand.Neg()
	}
	return nonce.Add(operand), nil
}

// MakeGenericChallenge computes the Fiat-Shamir challenge by hashing inputs.
// This implements the transformation from interactive to non-interactive Schnorr:
// e = H(R || P || m) reduced modulo the scalar field order.
//
// The challengeElementsAreLittleEndian parameter controls byte ordering:
//   - false: inputs are treated as big-endian (standard for most curves)
//   - true: inputs are reversed to little-endian before hashing (used by some variants)
//
// The hash output is reduced modulo n using FromWideBytes to avoid bias.
func MakeGenericChallenge[S Scalar[S]](scalarField ScalarField[S], hashFunc func() hash.Hash, challengeElementsAreLittleEndian bool, xs ...[]byte) (S, error) {
	if scalarField == nil {
		return *new(S), ErrInvalidArgument.WithMessage("scalar field is nil")
	}
	for _, x := range xs {
		if x == nil {
			return *new(S), ErrInvalidArgument.WithMessage("an input is nil")
		}
	}
	digest, err := hashing.Hash(hashFunc, xs...)
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("could not compute fiat shamir hash")
	}
	if challengeElementsAreLittleEndian {
		slices.Reverse(digest)
	}
	challenge, err := scalarField.FromWideBytes(digest)
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("could not compute fiat shamir challenge")
	}
	return challenge, nil
}
