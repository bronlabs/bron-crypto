package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

// TODO: make a proper scheme
func Verify[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](signature *Signature[S], suite *Suite[P, B, S], publicKey P, message []byte) error {
	nativeCurve := suite.curve.ToElliptic()
	// TODO: add AffineX, AffineY methods
	nativeX := new(big.Int).SetBytes(publicKey.Coordinates().Value()[0].Bytes())
	nativeY := new(big.Int).SetBytes(publicKey.Coordinates().Value()[1].Bytes())
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
