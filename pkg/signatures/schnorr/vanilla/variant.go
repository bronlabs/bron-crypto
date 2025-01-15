package vanilla

import (
	"slices"

	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
)

type EdDsaCompatibleVariant struct{}

var _ schnorr.Variant[EdDsaCompatibleVariant, []byte] = (*EdDsaCompatibleVariant)(nil)

var edDsaCompatibleVariant = &EdDsaCompatibleVariant{}

func NewEdDsaCompatibleVariant() *EdDsaCompatibleVariant {
	return edDsaCompatibleVariant
}

func (EdDsaCompatibleVariant) ComputeNonceCommitment(_, partialNonceCommitment curves.Point) curves.Point {
	return partialNonceCommitment
}

func (EdDsaCompatibleVariant) ComputeChallenge(signingSuite types.SigningSuite, nonceCommitment, publicKey curves.Point, message []byte) (curves.Scalar, error) {
	roinput := slices.Concat(
		nonceCommitment.ToAffineCompressed(),
		publicKey.ToAffineCompressed(),
		message,
	)

	e, err := schnorr.MakeGenericSchnorrChallenge(signingSuite, roinput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}
	return e, nil
}

func (EdDsaCompatibleVariant) ComputeResponse(_, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	return partialNonce.Add(challenge.Mul(partialSecretKey))
}

func (EdDsaCompatibleVariant) SerializeSignature(signature *schnorr.Signature[EdDsaCompatibleVariant, []byte]) []byte {
	return slices.Concat(signature.R.ToAffineCompressed(), bitstring.ReverseBytes(signature.S.Bytes()))
}

func (EdDsaCompatibleVariant) NewVerifierBuilder() schnorr.VerifierBuilder[EdDsaCompatibleVariant, []byte] {
	return &verifierBuilder{}
}
