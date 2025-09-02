package ecdsa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
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
	rx, err := bigR.AffineX()
	if err != nil {
		return -1, errs.WrapFailed(err, "cannot compute x")
	}
	ry, err := bigR.AffineY()
	if err != nil {
		return -1, errs.WrapFailed(err, "cannot compute y")
	}

	curve := algebra.StructureMustBeAs[Curve[P, B, S]](bigR.Structure())
	subGroupOrder := curve.Order().Value()

	var recoveryId int
	if !ry.IsOdd() {
		recoveryId = 0
	} else {
		recoveryId = 1
	}

	b, _, _ := rx.Cardinal().Value().Cmp(subGroupOrder)
	if b != 0 {
		recoveryId += 2
	}

	return recoveryId, nil
}

// RecoverPublicKey recovers PublicKey (point on the curve) based od messageHash, public key and recovery id.
func RecoverPublicKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](signature *Signature[S], suite *Suite[P, B, S], message []byte) (P, error) {
	var nilP P
	if signature.v == nil {
		return nilP, errs.NewIsNil("no recovery id")
	}

	// Calculate point R = (x1, x2) where
	//  x1 = r if (v & 2) == 0 or (r + n) if (v & 2) == 1
	//  y1 = value such that the curve equation is satisfied, y1 should be even when (v & 1) == 0, odd otherwise
	rx, err := suite.baseField.FromWideBytes(signature.r.Bytes())
	if err != nil {
		return nilP, errs.WrapFailed(err, "cannot calculate r_x")
	}
	if (*signature.v & 0b10) != 0 {
		n, err := suite.baseField.FromWideBytes(suite.curve.Order().Bytes())
		if err != nil {
			return nilP, errs.WrapFailed(err, "cannot calculate n")
		}
		rx = rx.Add(n)
	}
	r, err := suite.curve.FromAffineX(rx, (*signature.v&0b1) != 0)
	if err != nil {
		return nilP, errs.WrapFailed(err, "cannot calculate r")
	}

	// Calculate point Q (public key)
	//  Q = r^(-1)(sR - zG)
	digest, err := hashing.Hash(suite.hashFunc, message)
	if err != nil {
		return nilP, errs.WrapHashing(err, "cannot hash message")
	}
	z, err := DigestToScalar(suite.scalarField, digest)
	if err != nil {
		return nilP, errs.WrapFailed(err, "cannot calculate z")
	}

	rInv, err := signature.r.TryInv()
	if err != nil {
		return nilP, errs.WrapFailed(err, "cannot calculate inverse of r")
	}
	publicKey := (r.ScalarMul(signature.s).Sub(suite.curve.ScalarBaseMul(z))).ScalarMul(rInv)

	return publicKey, nil
}
