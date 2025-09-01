package ecdsa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// ComputeRecoveryId calculates recoveryId
// V is not part of the ECDSA standard and is a bitcoin-concept that allows recovery of the public key from the signature,
// because you want to verify the signature coming from an "address", not a public key.
// The values of V are:
//
//	v = 0 if R.y is even (= quadratic residue mod q)
//	v = 1 if R.y is not even
//	v = v if R.x is less than subgroup order
//	v = v + 2 if R.x is greater than subgroup order (but less than the field order which it always will be)
//
// Definition of recovery id described here: https://en.bitcoin.it/wiki/Message_signing
// Recovery process itself described in 4.1.6: http://www.secg.org/sec1-v2.pdf
// Note that V here is the same as recovery Id is EIP-155.
// Note that due to signature malleability, for us v is always either 0 or 1 (= we consider non-normalised signatures as invalid).
func ComputeRecoveryId[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](bigR P) (int, error) {
	rxField, err := bigR.AffineX()
	if err != nil {
		return -1, errs.WrapFailed(err, "cannot compute x")
	}
	rx := rxField.Cardinal().Value()
	ryField, err := bigR.AffineY()
	if err != nil {
		return -1, errs.WrapFailed(err, "cannot compute y")
	}
	ry := ryField.Cardinal().Value()

	curve := algebra.StructureMustBeAs[Curve[P, B, S]](bigR.Structure())
	subGroupOrder := curve.Order().Value()

	var recoveryId int
	if ry.Byte(0)&0b1 == 0 {
		recoveryId = 0
	} else {
		recoveryId = 1
	}

	b, _, _ := rx.Cmp(subGroupOrder)
	if b != 0 {
		recoveryId += 2
	}

	return recoveryId, nil
}

// RecoverPublicKey recovers PublicKey (point on the curve) based od messageHash, public key and recovery id.
//func RecoverPublicKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S], signature *Signature[S], message []byte) (P, error) {
//	var nilP P
//	if signature.V == nil {
//		return nilP, errs.NewIsNil("no recovery id")
//	}
//
//	// Calculate point R = (x1, x2) where
//	//  x1 = r if (v & 2) == 0 or (r + n) if (v & 2) == 1
//	//  y1 = value such that the curve equation is satisfied, y1 should be even when (v & 1) == 0, odd otherwise
//	baseField := algebra.StructureMustBeAs[algebra.PrimeField[B]](suite.Curve().BaseStructure())
//
//	rx := signature.r.Cardinal().Value()
//	if (*signature.v & 2) != 0 {
//		rx = new(saferith.Nat).Add(rx, suite.curve.Order().Value(), baseField.BitLen())
//	}
//	rxBytes := rx.Bytes()
//	if len(rxBytes) < 32 {
//		rxBytes = append(make([]byte, 32-len(rxBytes)), rxBytes...)
//	}
//	ryCompressed := []byte{byte(2)}
//	if (*signature.v & 1) != 0 {
//		ryCompressed[0]++
//	}
//	affine := slices.Concat(ryCompressed, rxBytes)
//	bigR, err := curve.Point().FromAffineCompressed(affine)
//	if err != nil {
//		return nilP, errs.WrapFailed(err, "cannot calculate R")
//	}
//
//	// Calculate point Q (public key)
//	//  Q = r^(-1)(sR - zG)
//	messageHash, err := hashing.Hash(hashFunc, message)
//	if err != nil {
//		return nilP, errs.WrapHashing(err, "cannot hash message")
//	}
//	zInt := BitsToInt(messageHash, curve)
//	z, err := curve.ScalarField().Element().SetBytes(zInt.Bytes())
//	if err != nil {
//		return nilP, errs.WrapFailed(err, "cannot calculate z")
//	}
//	rInv, err := signature.R.MultiplicativeInverse()
//	if err != nil {
//		return nilP, errs.WrapFailed(err, "cannot calculate inverse of r")
//	}
//	publicKey := (bigR.ScalarMul(signature.S).Sub(curve.ScalarBaseMult(z))).ScalarMul(rInv)
//
//	return publicKey, nil
//}
