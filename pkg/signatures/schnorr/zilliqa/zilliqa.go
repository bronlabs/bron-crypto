package zilliqa

import (
	"crypto/sha256"
	"encoding"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
)

type PublicKey schnorr.PublicKey

type Signature = schnorr.Signature[ZilliqaVariant]

var _ encoding.BinaryMarshaler = (*PublicKey)(nil)

var (
	curve     = k256.NewCurve()
	curveName = curve.Name()
	hashFunc  = sha256.New
)

func Verify(publicKey *PublicKey, signature *Signature, message []byte) error {
	v := zilliqaVariant.NewVerifierBuilder().
		WithPublicKey((*schnorr.PublicKey)(publicKey)).
		WithMessage(message).
		Build()

	//nolint:wrapcheck // forward errors
	return v.Verify(signature)
}

func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	return pk.A.ToAffineCompressed(), nil
}
