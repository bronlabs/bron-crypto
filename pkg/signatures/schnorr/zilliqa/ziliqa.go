package zilliqa

import (
	"crypto/sha256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

type PublicKey schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]

type Signature = schnorr.Signature[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar]

var (
	curve    = k256.NewCurve()
	hashFunc = sha256.New
)

func Verify(publicKey *PublicKey, signature *Signature, message []byte) error {
	v, err := zilliqaVariantInstance.NewVerifierBuilder().
		WithPublicKey((*schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])(publicKey)).
		WithMessage(message).
		Build()
	if err != nil {
		return errs.WrapFailed(err, "could not build the verifier")
	}

	//nolint:wrapcheck // forward errors
	return v.Verify(signature)
}

func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	return pk.A.ToAffineCompressed(), nil
}
