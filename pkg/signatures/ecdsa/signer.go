package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"
	"encoding/asn1"
	"io"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

// Signer produces ECDSA signatures using a private key.
// It supports both randomised signing (with a PRNG) and deterministic signing (RFC 6979).
type Signer[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite *Suite[P, B, S]
	sk    *PrivateKey[P, B, S]
	prng  io.Reader
}

// NewSigner creates a signer with the given suite, private key, and random source.
// For randomised suites, prng must be a cryptographically secure random source.
// For deterministic suites (RFC 6979), prng can be nil.
func NewSigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S], sk *PrivateKey[P, B, S], prng io.Reader) (*Signer[P, B, S], error) {
	if suite == nil || (prng == nil && !suite.IsDeterministic()) || sk == nil {
		return nil, ErrInvalidArgument.WithMessage("suite or prng or secret key is nil")
	}

	s := &Signer[P, B, S]{
		suite: suite,
		sk:    sk,
		prng:  prng,
	}
	return s, nil
}

// Sign creates an ECDSA signature on the given message.
//
// The signing process:
//  1. Hash the message using the suite's hash function
//  2. Generate ephemeral key k (random or deterministic per RFC 6979)
//  3. Compute R = k*G and set r = R.x mod n
//  4. Compute s = k^(-1) * (hash + r*d) mod n
//  5. Compute recovery ID v for public key recovery
//
// The returned signature includes r, s, and the recovery ID v.
func (s *Signer[P, B, S]) Sign(message []byte) (*Signature[S], error) {
	digest, err := hashing.Hash(s.suite.hashFunc, message)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("hashing failed")
	}
	nativeSk := s.sk.ToElliptic()

	var nativeR, nativeS *big.Int
	if s.suite.IsDeterministic() {
		asn1Sig, err := nativeSk.Sign(nil, digest, s.suite.hashId)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("signing failed")
		}

		// Parse ASN.1 DER-encoded signature to extract r and s
		var nativeEcdsaSig struct {
			R, S *big.Int
		}
		_, err = asn1.Unmarshal(asn1Sig, &nativeEcdsaSig)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("failed to parse ASN.1 signature")
		}
		nativeR, nativeS = nativeEcdsaSig.R, nativeEcdsaSig.S
	} else {
		nativeR, nativeS, err = nativeEcdsa.Sign(s.prng, nativeSk, digest)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("signing failed")
		}
	}

	rr, err := s.suite.scalarField.FromWideBytes(nativeR.Bytes())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot convert r")
	}
	ss, err := s.suite.scalarField.FromWideBytes(nativeS.Bytes())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot convert s")
	}

	for i := range 5 {
		v := i
		signature, err := NewSignature(rr, ss, &v)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("cannot create signature")
		}
		recoveredPk, err := RecoverPublicKey(s.suite, signature, message)
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("cannot recover public key")
		}
		if recoveredPk.Equal(s.sk.pk) {
			return signature, nil
		}
	}

	return nil, ErrVerificationFailed.WithMessage("cannot compute recovery id")
}

// IsDeterministic returns true if this signer uses RFC 6979 deterministic nonce generation.
func (s *Signer[P, B, S]) IsDeterministic() bool {
	return s.suite.IsDeterministic()
}
