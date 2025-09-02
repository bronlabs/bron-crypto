package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

// TODO: make a proper scheme
func Verify[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](signature *Signature[S], suite *Suite[P, B, S], publicKey P, message []byte) error {
	if signature == nil || suite == nil {
		return errs.NewArgument("signature, suite or public key cannot be nil")
	}
	if signature.s.IsZero() || signature.r.IsZero() {
		return errs.NewVerification("signature is invalid")
	}
	if publicKey.IsZero() {
		return errs.NewVerification("public key is invalid")
	}

	if signature.v != nil {
		recoveredPublicKey, err := RecoverPublicKey(signature, suite, message)
		if err != nil {
			return errs.WrapFailed(err, "cannot recover public key")
		}
		if !recoveredPublicKey.Equal(publicKey) {
			return errs.NewVerification("recovered public key does not match")
		}
	}

	nativeCurve := suite.curve.ToElliptic()
	// TODO: add AffineX, AffineY methods
	nativeX := utils.Must(publicKey.AffineX()).Cardinal().Big()
	nativeY := utils.Must(publicKey.AffineY()).Cardinal().Big()
	nativePublicKey := &nativeEcdsa.PublicKey{
		Curve: nativeCurve,
		X:     nativeX,
		Y:     nativeY,
	}

	digest, err := hashing.Hash(suite.hashFunc, message)
	if err != nil {
		return errs.WrapFailed(err, "cannot hash message")
	}
	nativeR := signature.r.Cardinal().Big()
	nativeS := signature.s.Cardinal().Big()
	ok := nativeEcdsa.Verify(nativePublicKey, digest, nativeR, nativeS)
	if !ok {
		return errs.NewVerification("invalid signature")
	}
	return nil
}
