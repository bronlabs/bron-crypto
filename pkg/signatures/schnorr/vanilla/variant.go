package vanilla

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"hash"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

type EdDsaCompatibleVariant[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
}

func NewEdDsaCompatibleVariant[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]](curve C) *EdDsaCompatibleVariant[P, B, S] {
	return &EdDsaCompatibleVariant[P, B, S]{}
}

func (EdDsaCompatibleVariant[P, B, S]) ComputeNonceCommitment(_, partialNonceCommitment P) P {
	return partialNonceCommitment
}

func (EdDsaCompatibleVariant[P, B, S]) ComputeChallenge(hashFunc func() hash.Hash, nonceCommitment, publicKey P, message []byte) (S, error) {
	roinput := slices.Concat(
		nonceCommitment.ToAffineCompressed(),
		publicKey.ToAffineCompressed(),
		message,
	)

	e, err := schnorr.MakeGenericSchnorrChallenge(hashFunc(), roinput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}
	return e, nil
}

func (EdDsaCompatibleVariant[P, B, S]) ComputeResponse(_, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	return partialNonce.Add(challenge.Mul(partialSecretKey))
}

func (EdDsaCompatibleVariant[P, B, S]) SerializeSignature(signature *schnorr.Signature[EdDsaCompatibleVariant, []byte]) []byte {
	return slices.Concat(signature.R.ToAffineCompressed(), bitstring.ReverseBytes(signature.S.Bytes()))
}

func (EdDsaCompatibleVariant[P, B, S]) NewVerifierBuilder() schnorr.VerifierBuilder[EdDsaCompatibleVariant, []byte] {
	return &verifierBuilder{}
}
