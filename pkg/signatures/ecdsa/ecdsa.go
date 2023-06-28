package ecdsa

import (
	"crypto/ecdsa"
	"hash"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/hashing"
)

type Signature struct {
	// V is not part of the ECDSA standard and is a bitcoin-concept that allows recovery of the public key from the signature,
	// because you want to verify the signature coming from an "address", not a public key.
	// The values of V are:
	//     v = 0 if R.y is even (= quadratic residue mod q)
	//     v = 1 if R.y is not even
	//     v = v if signature is normalized (= r is R.x modulo reduced)
	//     v = v + 2 if signature is not normalized
	// Process descirbed here: https://en.bitcoin.it/wiki/Message_signing
	// Note that V here is the same as recovery Id is EIP-155.
	// Note that due to signature malleability, for us v is always either 0 or 1 (= we consider non-normalized signatures as invalid)
	V    int
	R, S curves.Scalar
}

// Normalize the signature to a "low S" form. In ECDSA, signatures are
// of the form (r, s) where r and s are numbers lying in some finite
// field. Both (r, s) and (r, -s) are valid signatures of the same message
// so ECDSA does not have strong existential unforgeability
// We normalize to the low S form which ensures that the s value
// lies in the lower half of its range.
// See <https://en.bitcoin.it/wiki/BIP_0062#Low_S_values_in_signatures>
func (sigma *Signature) Normalize(curve *curves.Curve) error {
	isNormal, err := isNormalized(curve, sigma)
	if err != nil {
		return errs.WrapFailed(err, "could not check whether signature is in low s form")
	}
	if !isNormal {
		sigma.S = sigma.S.Neg()
	}
	return nil
}

// The values of V are:
//
//	v = 0 if R.y is even (= quadratic residue mod q)
//	v = 1 if R.y is not even
func (s *Signature) NormalizeAndSetRecoveryId(R curves.Point) error {
	curve, err := curves.GetCurveByName(R.CurveName())
	if err != nil {
		return errs.WrapInvalidCurve(err, "could not find curve of the public key")
	}
	if err := s.Normalize(curve); err != nil {
		return errs.WrapFailed(err, "could not normalize the signature")
	}
	wR, ok := R.(curves.WeierstrassPoint)
	if !ok {
		return errs.NewFailed("cannot convert R to a type that allows coordinate usage")
	}
	if wR.Y().IsEven() {
		s.V = 0
	} else {
		s.V = 1
	}
	return nil
}

func Verify(hashFunction func() hash.Hash, signature *Signature, R, publicKey curves.Point, message []byte) error {
	curve, err := curves.GetCurveByName(publicKey.CurveName())
	if err != nil {
		return errs.WrapInvalidCurve(err, "could not find curve of the public key")
	}
	ecdsaCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}

	if publicKey.IsIdentity() {
		return errs.NewVerificationFailed("public key is at infinity")
	}

	if err := verifyRecoveryId(R, signature); err != nil {
		return errs.WrapVerificationFailed(err, "invalid recovery id")
	}

	isNormal, err := isNormalized(curve, signature)
	if err != nil {
		return errs.WrapFailed(err, "could not check whether signature is in low s form")
	}
	if !isNormal {
		return errs.NewVerificationFailed("signature is not in low s form")
	}

	wPublicKey, ok := publicKey.(curves.WeierstrassPoint)
	if !ok {
		return errs.NewFailed("cannot convert public key to a type that allows coordinate usage")
	}
	ecdsaPublicKey := &ecdsa.PublicKey{
		Curve: ecdsaCurve,
		X:     wPublicKey.X().BigInt(),
		Y:     wPublicKey.Y().BigInt(),
	}

	digest, err := hashing.Hash(hashFunction, message)
	if err != nil {
		return errs.NewFailed("couldnot hash the plaintext")
	}

	if ok := ecdsa.Verify(ecdsaPublicKey, digest, signature.R.BigInt(), signature.S.BigInt()); !ok {
		return errs.NewVerificationFailed("ECDSA signature is invalid")
	}
	return nil
}

func isNormalized(curve *curves.Curve, signature *Signature) (bool, error) {
	// TODO: expose curve params of our implementations.
	ecdsaCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return false, errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}

	subgroupOrder, err := curve.Scalar.SetBigInt(ecdsaCurve.Params().N)
	if err != nil {
		return false, errs.WrapDeserializationFailed(err, "could not convert big int to scalar")
	}
	mid := subgroupOrder.Div(curve.Scalar.New(2))

	switch signature.S.Cmp(mid) {
	case -2:
		return false, errs.NewFailed("s and subgroup order are not in the same field")
	case -1, 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, errs.NewFailed("cmp function over a scalar is out of range. This should never happen")
	}
}

func verifyRecoveryId(R curves.Point, signature *Signature) error {
	if signature.V != 0 && signature.V != 1 {
		return errs.NewVerificationFailed("v is not 0 or 1. v=%d", signature.V)
	}

	wR, ok := R.(curves.WeierstrassPoint)
	if !ok {
		return errs.NewFailed("cannot convert R to a type that allows coordinate usage")
	}

	if wR.X().Cmp(signature.R) != 0 {
		return errs.NewVerificationFailed("provided signature's r is not the x coordinate of the provided R")
	}

	if wR.Y().IsEven() && signature.V != 0 {
		return errs.NewVerificationFailed("R.y is even but v is nonzero")
	}

	if !wR.Y().IsEven() && signature.V == 0 {
		return errs.NewVerificationFailed("R.y is not even but v is zero")
	}
	return nil
}
