package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

// Verifier validates ECDSA signatures against public keys.
// It uses the cryptographic parameters from the suite to ensure consistent
// hash function usage between signing and verification.
type Verifier[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite *Suite[P, B, S]
}

// NewVerifier creates a verifier with the given cryptographic suite.
// The suite defines the curve and hash function used for verification.
func NewVerifier[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S]) (*Verifier[P, B, S], error) {
	if suite == nil {
		return nil, errs.NewIsNil("suite")
	}

	v := &Verifier[P, B, S]{
		suite: suite,
	}
	return v, nil
}

// Verify checks that a signature is valid for a message under a public key.
//
// The verification process (per SEC 1 v2.0 Section 4.1.4):
//  1. Hash the message using the suite's hash function
//  2. Compute u1 = z * s^(-1) mod n and u2 = r * s^(-1) mod n
//  3. Compute R' = u1*G + u2*Q (where Q is the public key)
//  4. Accept if R'.x ≡ r (mod n)
//
// If the signature includes a recovery ID (v), this method additionally verifies
// that the recovered public key matches the provided public key, providing an
// extra integrity check.
//
// Returns nil if the signature is valid, or an error describing the failure.
func (v *Verifier[P, B, S]) Verify(s *Signature[S], pk *PublicKey[P, B, S], m []byte) error {
	if s == nil || pk == nil {
		return errs.NewArgument("signature & public key cannot be nil")
	}

	if s.v != nil {
		recoveredPublicKey, err := RecoverPublicKey(v.suite, s, m)
		if err != nil {
			return errs.WrapFailed(err, "cannot recover public key")
		}
		if !recoveredPublicKey.Equal(pk) {
			return errs.NewVerification("recovered public key does not match")
		}
	}

	digest, err := hashing.Hash(v.suite.hashFunc, m)
	if err != nil {
		return errs.WrapFailed(err, "cannot hash message")
	}

	nativePk := pk.ToElliptic()
	nativeR, nativeS := s.ToElliptic()
	ok := nativeEcdsa.Verify(nativePk, digest, nativeR, nativeS)
	if !ok {
		return errs.NewVerification("invalid signature")
	}
	return nil
}
