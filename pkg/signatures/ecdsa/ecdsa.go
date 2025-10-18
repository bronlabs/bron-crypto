package ecdsa

import (
	"bytes"
	"crypto/elliptic"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

const Name signatures.Name = "ECDSA"

type Curve[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] interface {
	curves.Curve[P, B, S]
	FromAffineX(x B, b bool) (P, error)
	ToElliptic() elliptic.Curve
}

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
	subGroupOrder := curve.Order()

	var recoveryId int
	if !ry.IsOdd() {
		recoveryId = 0
	} else {
		recoveryId = 1
	}

	if base.PartialCompare(rx.Cardinal(), subGroupOrder).Is(base.Ordering(base.GreaterThan)) {
		recoveryId += 2
	}

	return recoveryId, nil
}

// RecoverPublicKey recovers PublicKey (point on the curve) based od messageHash, public key and recovery id.
func RecoverPublicKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S], signature *Signature[S], message []byte) (*PublicKey[P, B, S], error) {
	if suite == nil || signature == nil {
		return nil, errs.NewIsNil("suite or signature")
	}
	if signature.v == nil {
		return nil, errs.NewIsNil("no recovery id")
	}

	// Calculate point R = (x1, x2) where
	//  x1 = r if (v & 2) == 0 or (r + n) if (v & 2) == 1
	//  y1 = value such that the curve equation is satisfied, y1 should be even when (v & 1) == 0, odd otherwise
	rx, err := suite.baseField.FromWideBytes(signature.r.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate r_x")
	}
	if (*signature.v & 0b10) != 0 {
		n, err := suite.baseField.FromWideBytes(suite.curve.Order().Bytes())
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot calculate n")
		}
		rx = rx.Add(n)
	}
	r, err := suite.curve.FromAffineX(rx, (*signature.v&0b1) != 0)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate r")
	}

	// Calculate point Q (public key)
	//  Q = r^(-1)(sR - zG)
	digest, err := hashing.Hash(suite.hashFunc, message)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash message")
	}
	z, err := DigestToScalar(suite.scalarField, digest)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate z")
	}

	rInv, err := signature.r.TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate inverse of r")
	}
	pkValue := (r.ScalarMul(signature.s).Sub(suite.curve.ScalarBaseMul(z))).ScalarMul(rInv)
	pk, err := NewPublicKey(pkValue)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate public key")
	}

	return pk, nil
}

// DigestToScalar sets scalar to the left-most bits of hash, according to
// FIPS 186-5, Section 6.4.1, point 2 and Section 6.4.2, point 3.
func DigestToScalar[S algebra.PrimeFieldElement[S]](field algebra.PrimeField[S], digest []byte) (S, error) {
	// ECDSA asks us to take the left-most log2(N) bits of hash, and use them as
	// an integer modulo N. This is the absolute worst of all worlds: we still
	// have to reduce, because the result might still overflow N, but to take
	// the left-most bits for P-521 we have to do a right shift.
	var nilS S
	n := field.ElementSize()
	if size := n; len(digest) >= size {
		digest = digest[:size]
		if excess := len(digest)*8 - field.BitLen(); excess > 0 {
			var err error
			digest, err = rightShift(digest, excess)
			if err != nil {
				return nilS, errs.WrapFailed(err, "internal error")
			}
		}
	}
	s, err := field.FromWideBytes(digest)
	if err != nil {
		return nilS, errs.WrapFailed(err, "truncated digest is too long")
	}
	return s, nil
}

// rightShift implements the right shift necessary for bits2int, which takes the
// leftmost bits of either the hash or HMAC_DRBG output.
//
// Note how taking the rightmost bits would have been as easy as masking the
// first byte, but we can't have nice things.
func rightShift(b []byte, shift int) ([]byte, error) {
	if shift <= 0 || shift >= 8 {
		return nil, errs.NewFailed("shift can only be by 1 to 7 bits")
	}
	b = bytes.Clone(b)
	for i := len(b) - 1; i >= 0; i-- {
		b[i] >>= shift
		if i > 0 {
			b[i] |= b[i-1] << (8 - shift)
		}
	}
	return b, nil
}
