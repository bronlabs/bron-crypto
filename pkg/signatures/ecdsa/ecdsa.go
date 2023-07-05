package ecdsa

import (
	"crypto/ecdsa"
	"hash"
	"strings"

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
	//     v = v if R.x is less than subgroup order
	//     v = v + 2 if R.x is greater than subgroup order (but less than the field order which it always will be)
	// Definition of recovery id described here: https://en.bitcoin.it/wiki/Message_signing
	// Recovery process itself described in 4.1.6: http://www.secg.org/sec1-v2.pdf
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
	if err := isNormalized(curve, sigma); err != nil {
		// TODO: check for error type
		if strings.HasPrefix(err.Error(), "[VERIFICATION_FAILED]") {
			sigma.S = sigma.S.Neg()
		} else {
			return errs.WrapFailed(err, "normalization check failed")
		}
	}
	return nil
}

// The values of V are:
//
//	v = 0 if R.y is even (= quadratic residue mod q)
//	v = 1 if R.y is not even
//	v = v if R.x is less than subgroup order
//	v = v + 2 if R.x is greater than subgroup order (but less than the field order which it always will be)
func (s *Signature) SetRecoveryId(R curves.Point) error {
	curve, err := curves.GetCurveByName(R.CurveName())
	if err != nil {
		return errs.WrapInvalidCurve(err, "could not find curve of the public key")
	}
	ecdsaCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}
	subGroupOrder := ecdsaCurve.Params().N
	wR, ok := R.(curves.WeierstrassPoint)
	if !ok {
		return errs.NewFailed("cannot convert R to a type that allows coordinate usage")
	}
	if wR.Y().IsEven() {
		s.V = 0
	} else {
		s.V = 1
	}

	switch wR.X().BigInt().Cmp(subGroupOrder) {
	case -1:
		break
	case 0:
		return errs.NewFailed("x coordinate of the signature is equal to subGroupOrder")
	case 1:
		s.V = s.V + 2
	default:
		return errs.NewFailed("big int cmp failed. We should never be here.")
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

	if err := isNormalized(curve, signature); err != nil {
		return errs.WrapVerificationFailed(err, "normalization check failed")
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

func isNormalized(curve *curves.Curve, signature *Signature) error {
	// TODO: expose curve params of our implementations.
	ecdsaCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}

	subgroupOrder, err := curve.Scalar.SetBigInt(ecdsaCurve.Params().N)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "could not convert big int to scalar")
	}
	mid := subgroupOrder.Div(curve.Scalar.New(2))

	switch signature.S.Cmp(mid) {
	case -2:
		return errs.NewFailed("s and subgroup order are not in the same field")
	case -1, 0:
		return nil
	case 1:
		return errs.NewVerificationFailed("signature is not normalized")
	default:
		return errs.NewFailed("cmp function over a scalar is out of range. This should never happen")
	}
}

func verifyRecoveryId(R curves.Point, signature *Signature) error {
	if signature.V != 0 && signature.V != 1 && signature.V != 2 && signature.V != 3 {
		return errs.NewVerificationFailed("v is not 0 or 1 or 2 or 3. v=%d", signature.V)
	}

	wR, ok := R.(curves.WeierstrassPoint)
	if !ok {
		return errs.NewFailed("cannot convert R to a type that allows coordinate usage")
	}
	if wR.X().Cmp(signature.R) != 0 {
		return errs.NewVerificationFailed("provided signature's r is not the x coordinate of the provided R")
	}

	curve, err := curves.GetCurveByName(R.CurveName())
	if err != nil {
		return errs.WrapInvalidCurve(err, "could not find curve of the public key")
	}
	ecdsaCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return errs.WrapInvalidCurve(err, "knox curve cannot be converted to Go's elliptic curve representation")
	}
	xCoordCmpSubGroupOrder := wR.X().BigInt().Cmp(ecdsaCurve.Params().N)
	if xCoordCmpSubGroupOrder == 0 {
		return errs.NewVerificationFailed("R.x == q")
	}
	if wR.Y().IsEven() {
		// x < subgroup order
		if xCoordCmpSubGroupOrder == -1 && signature.V != 0 {
			return errs.NewVerificationFailed("R.y is even and R.x < q and v != 0")
		}
		// x > subgroup order
		if xCoordCmpSubGroupOrder == 1 && signature.V != 2 {
			return errs.NewVerificationFailed("R.y is even and R.x > q and v != 2")
		}
	}
	if wR.Y().IsOdd() {
		// x < subgroup order
		if xCoordCmpSubGroupOrder == -1 && signature.V != 1 {
			return errs.NewVerificationFailed("R.y is not even and R.x < q and v != 1")
		}
		// x > subgroup order
		if xCoordCmpSubGroupOrder == 1 && signature.V != 3 {
			return errs.NewVerificationFailed("R.y is not even and R.x > q and v != 3")
		}
	}
	return nil
}
