// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm (ECDSA)
// as specified in FIPS 186-5 and SEC 1, Version 2.0.
//
// ECDSA is a widely-used digital signature scheme based on elliptic curve cryptography.
// It provides the same level of security as RSA but with smaller key sizes, making it
// efficient for constrained environments.
//
// This implementation supports:
//   - Standard randomised ECDSA (requires secure random source)
//   - Deterministic ECDSA per RFC 6979 (no random source needed)
//   - Public key recovery from signatures (Bitcoin-style recovery ID)
//   - Signature normalisation to low-S form (BIP-62 compatible)
//
// References:
//   - FIPS 186-5: https://csrc.nist.gov/pubs/fips/186-5/final
//   - SEC 1 v2.0: https://www.secg.org/sec1-v2.pdf
//   - RFC 6979: https://www.rfc-editor.org/rfc/rfc6979
package ecdsa

import (
	"bytes"
	"crypto/elliptic"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

// Name is the canonical identifier for this signature scheme.
const Name signatures.Name = "ECDSA"

// Curve extends the base curves.Curve interface with ECDSA-specific operations.
// It adds point recovery from x-coordinate and conversion to Go's standard library
// elliptic curve representation for interoperability.
type Curve[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] interface {
	curves.Curve[P, B, S]
	// FromAffineX recovers a curve point from its x-coordinate. The boolean parameter
	// selects which of the two possible y values to use (true for odd y).
	FromAffineX(x B, b bool) (P, error)
	// ToElliptic returns the equivalent Go standard library elliptic curve.
	ToElliptic() elliptic.Curve
}

// ComputeRecoveryId calculates the recovery ID (v) for public key recovery from an ECDSA signature.
//
// The recovery ID is not part of the ECDSA standard but is a Bitcoin-originated concept that
// enables recovering the public key from just the signature and message hash. This is useful
// when verifying signatures against addresses rather than full public keys.
//
// The recovery ID encodes:
//   - Bit 0: y-coordinate parity (0 = even, 1 = odd)
//   - Bit 1: x-coordinate overflow (0 = r < n, 1 = r >= n where n is the subgroup order)
//
// Due to order of the base field being ~== order of the curve group, v is typically 0 or 1 in practice.
//
// References:
//   - Bitcoin message signing: https://en.bitcoin.it/wiki/Message_signing
//   - SEC 1 v2.0 Section 4.1.6: https://www.secg.org/sec1-v2.pdf
//   - EIP-155 (Ethereum): recovery ID is equivalent to v in Ethereum transactions
func ComputeRecoveryId[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](bigR P) (int, error) {
	rx, err := bigR.AffineX()
	if err != nil {
		return -1, errs2.Wrap(err).WithMessage("cannot compute x")
	}
	ry, err := bigR.AffineY()
	if err != nil {
		return -1, errs2.Wrap(err).WithMessage("cannot compute y")
	}

	curve := algebra.StructureMustBeAs[Curve[P, B, S]](bigR.Structure())
	subGroupOrder := curve.Order()

	var recoveryId int
	if !ry.IsOdd() {
		recoveryId = 0
	} else {
		recoveryId = 1
	}

	if base.PartialCompare(rx.Cardinal(), subGroupOrder).IsGreaterThan() {
		recoveryId += 2
	}

	return recoveryId, nil
}

// RecoverPublicKey recovers the signer's public key from an ECDSA signature with recovery ID.
//
// This implements the public key recovery algorithm from SEC 1 v2.0, Section 4.1.6.
// Given a valid signature (r, s, v) and the original message, the algorithm:
//  1. Reconstructs the curve point R from r and recovery ID v
//  2. Computes Q = r^(-1) * (s*R - z*G) where z is the message hash and G is the generator
//
// The signature must include a valid recovery ID (v field). If the recovered public key
// does not match the expected signer, verification will fail.
//
// Reference: SEC 1 v2.0 Section 4.1.6: https://www.secg.org/sec1-v2.pdf
func RecoverPublicKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S], signature *Signature[S], message []byte) (*PublicKey[P, B, S], error) {
	if suite == nil || signature == nil {
		return nil, ErrInvalidArgument.WithMessage("suite or signature is nil")
	}
	if signature.v == nil {
		return nil, ErrInvalidArgument.WithMessage("no recovery id")
	}

	// Calculate point R = (x1, x2) where
	//  x1 = r if (v & 2) == 0 or (r + n) if (v & 2) == 1
	//  y1 = value such that the curve equation is satisfied, y1 should be even when (v & 1) == 0, odd otherwise
	rx, err := suite.baseField.FromWideBytes(signature.r.Bytes())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot calculate r_x")
	}
	if (*signature.v & 0b10) != 0 {
		n, err := suite.baseField.FromWideBytes(suite.curve.Order().Bytes())
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("cannot calculate n")
		}
		rx = rx.Add(n)
	}
	r, err := suite.curve.FromAffineX(rx, (*signature.v&0b1) != 0)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot calculate r")
	}

	// Calculate point Q (public key)
	//  Q = r^(-1)(sR - zG)
	digest, err := hashing.Hash(suite.hashFunc, message)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot hash message")
	}
	z, err := DigestToScalar(suite.scalarField, digest)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot calculate z")
	}

	rInv, err := signature.r.TryInv()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot calculate inverse of r")
	}
	pkValue := (r.ScalarMul(signature.s).Sub(suite.curve.ScalarBaseMul(z))).ScalarMul(rInv)
	pk, err := NewPublicKey(pkValue)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot calculate public key")
	}

	return pk, nil
}

// DigestToScalar converts a message digest to a scalar value for ECDSA operations.
//
// Per FIPS 186-5 Section 6.4, the leftmost min(bitlen(digest), bitlen(n)) bits of the
// hash are used, where n is the subgroup order. For curves like P-521 where the order
// is not byte-aligned, a right shift is performed to extract the correct bits.
//
// The result is reduced modulo n to produce a valid scalar in the curve's scalar field.
//
// Reference: FIPS 186-5 Section 6.4.1 point 2 and Section 6.4.2 point 3
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
				return nilS, errs2.Wrap(err).WithMessage("internal error")
			}
		}
	}
	s, err := field.FromWideBytes(digest)
	if err != nil {
		return nilS, errs2.Wrap(err).WithMessage("truncated digest is too long")
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
		return nil, ErrFailed.WithMessage("shift can only be by 1 to 7 bits")
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
