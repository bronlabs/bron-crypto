package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

// Verifier validates ECDSA signatures against public keys.
// It uses the cryptographic parameters from the suite to ensure consistent
// hash function usage between signing and verification.
type Verifier[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite              *Suite[P, B, S]
	mustBeNonMalleable bool
}

// VerifyNonMalleably configures the verifier to reject non-normalised signatures, which are vulnerable to malleability attacks.
func VerifyNonMalleably[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](vf *Verifier[P, B, S]) error {
	if vf == nil {
		return signatures.ErrInvalidArgument.WithMessage("verifier is nil")
	}
	vf.mustBeNonMalleable = true
	return nil
}

// NewVerifier creates a verifier with the given cryptographic suite.
// The suite defines the curve and hash function used for verification.
// Note that the output verifier does not enforce non-malleability by default; apply the VerifyNonMalleably option to enable that check.
func NewVerifier[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S]) (*Verifier[P, B, S], error) {
	if suite == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("suite is nil")
	}

	v := &Verifier[P, B, S]{
		suite:              suite,
		mustBeNonMalleable: false,
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
		return signatures.ErrInvalidArgument.WithMessage("signature & public key cannot be nil")
	}
	if v.mustBeNonMalleable && !s.IsNormalized() {
		return signatures.ErrVerificationFailed.WithMessage("signature is not in normalised form")
	}

	if s.v != nil {
		recoveredPublicKey, err := RecoverPublicKey(v.suite, s, m)
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot recover public key")
		}
		if !recoveredPublicKey.Equal(pk) {
			return signatures.ErrVerificationFailed.WithMessage("recovered public key does not match")
		}
	}

	digest, err := hashing.Hash(v.suite.hashFunc, m)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot hash message")
	}

	nativePk, err := pk.ToElliptic()
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot convert public key to native ECDSA format")
	}
	if nativePk == nil {
		return signatures.ErrInvalidArgument.WithMessage("public key cannot be converted to native ECDSA format")
	}
	nativeR, nativeS := s.ToElliptic()
	ok := nativeEcdsa.Verify(nativePk, digest, nativeR, nativeS)
	if !ok {
		return signatures.ErrVerificationFailed.WithMessage("invalid signature")
	}
	return nil
}
