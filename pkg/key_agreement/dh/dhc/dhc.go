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
	k := curve.ScalarField().Element().SetNat(curve.CoFactor())
	kInv, err := k.MultiplicativeInverse()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get inverse")
	}
	t := kInv.Mul(myPrivateKey)
	// step 2
	P := otherPartyPublicKey.ScalarMul(k.Mul(t))
	// step 3
	if P.IsAdditiveIdentity() {
		return nil, errs.NewIsIdentity("invalid public key")
	}
	// step 4
	z := P.AffineX()
	// step 5
	return z, nil
}
