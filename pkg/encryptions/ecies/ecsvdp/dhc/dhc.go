package dhc

import (
	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
)

func DeriveSharedSecretValue(myPrivateKey curves.Scalar, otherPartyPublicKey curves.Point) (curves.FieldElement, error) {
	if myPrivateKey.CurveName() != otherPartyPublicKey.CurveName() {
		return nil, errs.NewInvalidCurve("curves of my private key and other guy's public key are not the same")
	}
	// assumption 1
	if myPrivateKey.IsZero() {
		return nil, errs.NewIsZero("invalid private key")
	}
	curve := myPrivateKey.Curve()
	// step 1
	kInv, err := curve.Profile().Cofactor().Invert()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute inverse of cofactor")
	}
	t := kInv.Mul(myPrivateKey)
	// step 2
	P := otherPartyPublicKey.Mul(curve.Profile().Cofactor().Mul(t))
	// step 3
	if P.IsIdentity() {
		return nil, errs.NewIsIdentity("invalid public key")
	}
	// step 4
	z := P.X()
	// step 5
	return z, nil
}
