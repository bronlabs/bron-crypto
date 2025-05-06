package zilliqa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"hash"
	"slices"
	
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

var (
	zilliqaVariantInstance = &ZilliqaVariant{}
)

type ZilliqaVariant struct{} //nolint:revive // keep consistent naming

func NewZilliqaVariant() *ZilliqaVariant {
	return zilliqaVariantInstance
}

func (ZilliqaVariant) ComputeNonceCommitment(_, partialNonceCommitment *k256.Point) *k256.Point {
	return partialNonceCommitment
}

func (ZilliqaVariant) ComputeChallenge(hashFunc func() hash.Hash, nonceCommitment, publicKey *k256.Point, message []byte) (*k256.Scalar, error) {
	roinput := slices.Concat(
		nonceCommitment.ToAffineCompressed(),
		publicKey.ToAffineCompressed(),
		message,
	)

	e, err := schnorr.MakeGenericSchnorrChallenge(k256.NewScalarField(), hashFunc, schnorr.BigEndian, roinput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}
	return e, nil
}

func (ZilliqaVariant) ComputeResponse(_, _ *k256.Point, partialNonce, partialSecretKey, challenge *k256.Scalar) *k256.Scalar {
	return partialNonce.Sub(challenge.Mul(partialSecretKey))
}

func (ZilliqaVariant) SerializeSignature(signature *schnorr.Signature[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar]) []byte {
	return slices.Concat(signature.E.Bytes(), signature.S.Bytes())
}
func (ZilliqaVariant) NewVerifierBuilder() schnorr.VerifierBuilder[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	return &verifierBuilder{}
}
