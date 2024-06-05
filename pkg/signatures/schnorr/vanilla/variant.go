package vanilla

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
)

type EdDsaCompatibleVariant struct{}

var _ schnorr.Variant[EdDsaCompatibleVariant] = (*EdDsaCompatibleVariant)(nil)

var edDsaCompatibleVariant = &EdDsaCompatibleVariant{}

func NewEdDsaCompatibleVariant() *EdDsaCompatibleVariant {
	return edDsaCompatibleVariant
}

func (EdDsaCompatibleVariant) ComputeNonceCommitment(_, partialNonceCommitment curves.Point) curves.Point {
	return partialNonceCommitment
}

func (EdDsaCompatibleVariant) ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte {
	return slices.Concat(nonceCommitment.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
}

func (EdDsaCompatibleVariant) ComputeResponse(_, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	return partialNonce.Add(challenge.Mul(partialSecretKey))
}

func (EdDsaCompatibleVariant) SerializeSignature(signature *Signature) []byte {
	return slices.Concat(signature.R.ToAffineCompressed(), bitstring.ReverseBytes(signature.S.Bytes()))
}

func (EdDsaCompatibleVariant) NewVerifierBuilder() schnorr.VerifierBuilder[EdDsaCompatibleVariant] {
	return &verifierBuilder{}
}
