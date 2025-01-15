package zilliqa

import (
	"slices"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
)

type ZilliqaVariant struct{} //nolint:revive // keep consistent naming

var _ schnorr.Variant[ZilliqaVariant, []byte] = (*ZilliqaVariant)(nil)

var zilliqaVariant = &ZilliqaVariant{}

func NewZilliqaVariant() *ZilliqaVariant {
	return zilliqaVariant
}

func (ZilliqaVariant) ComputeNonceCommitment(_, partialNonceCommitment curves.Point) curves.Point {
	return partialNonceCommitment
}

func (ZilliqaVariant) ComputeChallenge(signingSuite types.SigningSuite, nonceCommitment, publicKey curves.Point, message []byte) (curves.Scalar, error) {
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

func (ZilliqaVariant) ComputeResponse(_, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	return partialNonce.Sub(challenge.Mul(partialSecretKey))
}

func (ZilliqaVariant) SerializeSignature(signature *schnorr.Signature[ZilliqaVariant, []byte]) []byte {
	return slices.Concat(signature.E.Bytes(), signature.S.Bytes())
}
func (ZilliqaVariant) NewVerifierBuilder() schnorr.VerifierBuilder[ZilliqaVariant, []byte] {
	return &verifierBuilder{}
}
