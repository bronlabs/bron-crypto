package dh

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curve25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	ecsdvpDhc "github.com/copperexchange/krypton-primitives/pkg/key_agreement/dh/dhc"
)

func DiffieHellman(myPrivateKey curves.Scalar, otherPartyPublicKey curves.Point) (curves.BaseFieldElement, error) {
	curveName := myPrivateKey.ScalarField().Curve().Name()
	if curveName != otherPartyPublicKey.Curve().Name() {
		return nil, errs.NewCurve("curves of my private key and other guy's public key are not the same")
	}

	if curveName == curve25519.Name {
		if curve25519PublicKey, ok := otherPartyPublicKey.(*curve25519.Point); ok {
			return curve25519PublicKey.X25519(myPrivateKey).AffineX(), nil
		}

		return nil, errs.NewCurve("curve is not curve25519")
	} else {
		//nolint:wrapcheck // done deliberately to forward errors
		return ecsdvpDhc.DeriveSharedSecretValue(myPrivateKey, otherPartyPublicKey)
	}
}
