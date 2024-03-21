package zilliqa

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
)

type ZilliqaVariant struct{} //nolint:revive // keep consistent naming

var _ schnorr.Variant[ZilliqaVariant] = (*ZilliqaVariant)(nil)

var zilliqaVariant = &ZilliqaVariant{}

func NewZilliqaVariant() *ZilliqaVariant {
	return zilliqaVariant
}

func (ZilliqaVariant) ComputeNonceCommitment(_, partialNonceCommitment curves.Point) curves.Point {
	return partialNonceCommitment
}

func (ZilliqaVariant) ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte {
	return slices.Concat(nonceCommitment.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
}

func (ZilliqaVariant) ComputeResponse(_, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	return partialNonce.Sub(challenge.Mul(partialSecretKey))
}

func (ZilliqaVariant) SerializeSignature(signature *Signature) []byte {
	return slices.Concat(signature.E.Bytes(), signature.S.Bytes())
}
func (ZilliqaVariant) NewVerifierBuilder() schnorr.VerifierBuilder[ZilliqaVariant] {
	return &verifierBuilder{}
}
