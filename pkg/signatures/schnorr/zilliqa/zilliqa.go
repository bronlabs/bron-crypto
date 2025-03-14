package zilliqa

import (
	"crypto/sha256"
	"encoding"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

type PublicKey schnorr.PublicKey

type Signature = schnorr.Signature[ZilliqaVariant, []byte]

var _ encoding.BinaryMarshaler = (*PublicKey)(nil)

var (
	curve     = k256.NewCurve()
	curveName = curve.Name()
	hashFunc  = sha256.New
)

func Verify(publicKey *PublicKey, signature *Signature, message []byte) error {
	v, err := zilliqaVariant.NewVerifierBuilder().
		WithPublicKey((*schnorr.PublicKey)(publicKey)).
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
