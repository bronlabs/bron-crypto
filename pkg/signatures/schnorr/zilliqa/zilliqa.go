package zilliqa

import (
	"crypto/sha256"
	"encoding"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

type Signature schnorr.Signature

var _ encoding.BinaryMarshaler = (*Signature)(nil)

type PublicKey schnorr.PublicKey

var _ encoding.BinaryMarshaler = (*PublicKey)(nil)

var (
	curve     = k256.NewCurve()
	curveName = curve.Name()
	hashFunc  = sha256.New
)

func Verify(publicKey *PublicKey, signature *Signature, message []byte) error {
	if publicKey == nil || signature == nil || len(message) == 0 {
		return errs.NewIsNil("argument is empty")
	}

	if publicKey.A == nil || publicKey.A.Curve().Name() != curveName {
		return errs.NewFailed("incompatible public key")
	}

	if signature.E == nil || signature.E.ScalarField().Curve().Name() != curveName || signature.S == nil || signature.S.ScalarField().Curve().Name() != curveName {
		return errs.NewFailed("incompatible signature")
	}

	if signature.E.IsZero() || signature.S.IsZero() {
		return errs.NewVerification("invalid E or S value, cannot be zero")
	}

	l := publicKey.A.Mul(signature.E)
	r := curve.ScalarBaseMult(signature.S)
	q := r.Add(l)

	if signature.R != nil && !signature.R.Equal(q) {
		return errs.NewFailed("incompatible signature")
	}

	protocol, err := types.NewSignatureProtocol(curve, hashFunc)
	if err != nil {
		return errs.WrapFailed(err, "cannot create protocol")
	}
	eCheck, err := schnorr.MakeSchnorrCompatibleChallenge(protocol, q.ToAffineCompressed(), publicKey.A.ToAffineCompressed(), message)
	if err != nil {
		return errs.WrapFailed(err, "cannot compute challenge")
	}

	if !signature.E.Equal(eCheck) {
		return errs.NewVerification("invalid signature")
	}

	return nil
}

func (s *Signature) MarshalBinary() (data []byte, err error) {
	return slices.Concat(s.E.Bytes(), s.S.Bytes()), nil
}

func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	return pk.A.ToAffineCompressed(), nil
}
