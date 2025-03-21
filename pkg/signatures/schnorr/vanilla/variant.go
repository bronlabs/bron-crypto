package vanilla

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"hash"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

type EdDsaCompatibleVariant[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
}

func NewEdDsaCompatibleVariant[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]]() *EdDsaCompatibleVariant[P, B, S] {
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

	scalarField, err := curves.GetPointScalarField(publicKey)
	if err != nil {
		return *new(S), err
	}
	e, err := schnorr.MakeGenericSchnorrChallenge(scalarField, hashFunc, roinput)
	if err != nil {
		return *new(S), errs.WrapFailed(err, "cannot create challenge scalar")
	}
	return e, nil
}

func (EdDsaCompatibleVariant[P, B, S]) ComputeResponse(_, _ P, partialNonce, partialSecretKey, challenge S) S {
	return partialNonce.Add(challenge.Mul(partialSecretKey))
}

func (EdDsaCompatibleVariant[P, B, S]) SerializeSignature(signature *schnorr.Signature[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S]) []byte {
	sBytes := signature.S.Bytes()
	slices.Reverse(sBytes)
	return slices.Concat(signature.R.ToAffineCompressed(), sBytes)
}

func (EdDsaCompatibleVariant[P, B, S]) NewVerifierBuilder() schnorr.VerifierBuilder[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S] {
	return &verifierBuilder[P, B, S]{}
}
