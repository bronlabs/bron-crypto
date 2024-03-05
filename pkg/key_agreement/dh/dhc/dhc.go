package dhc

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func DeriveSharedSecretValue(myPrivateKey curves.Scalar, otherPartyPublicKey curves.Point) (curves.BaseFieldElement, error) {
	curveName := myPrivateKey.ScalarField().Curve().Name()
	if curveName != otherPartyPublicKey.Curve().Name() {
		return nil, errs.NewCurve("curves of my private key and other guy's public key are not the same")
	}

	// assumption 1
	if myPrivateKey.IsZero() {
		return nil, errs.NewIsZero("invalid private key")
	}
	curve := myPrivateKey.ScalarField().Curve()
	// step 1
	k := curve.ScalarField().Element().SetNat(curve.Cofactor())
	kInv := k.MultiplicativeInverse()
	t := kInv.Mul(myPrivateKey)
	// step 2
	P := otherPartyPublicKey.Mul(k.Mul(t))
	// step 3
	if P.IsIdentity() {
		return nil, errs.NewIsIdentity("invalid public key")
	}
	// step 4
	z := P.AffineX()
	// step 5
	return z, nil
}
