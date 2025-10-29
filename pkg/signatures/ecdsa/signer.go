package ecdsa

import (
	"crypto"
	nativeEcdsa "crypto/ecdsa"
	"encoding/asn1"
	"hash"
	"io"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

// signerOpts implements crypto.SignerOpts for deterministic signing
type signerOpts struct {
	hash hash.Hash
}

func (s signerOpts) HashFunc() crypto.Hash {
	// Map hash.Hash to crypto.Hash based on output size
	switch s.hash.Size() {
	case 20:
		return crypto.SHA1
	case 28:
		return crypto.SHA224
	case 32:
		return crypto.SHA256
	case 48:
		return crypto.SHA384
	case 64:
		return crypto.SHA512
	default:
		return 0 // Unknown hash
	}
}

type Signer[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite *Suite[P, B, S]
	sk    *PrivateKey[P, B, S]
	prng  io.Reader
}

func NewDeterministicSigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S], sk *PrivateKey[P, B, S]) (*Signer[P, B, S], error) {
	if suite == nil || sk == nil {
		return nil, errs.NewIsNil("suite or secret key is nil")
	}

	s := &Signer[P, B, S]{
		suite: suite,
		sk:    sk,
		prng:  nil,
	}
	return s, nil
}

func NewSigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S], sk *PrivateKey[P, B, S], prng io.Reader) (*Signer[P, B, S], error) {
	if suite == nil || prng == nil || sk == nil {
		return nil, errs.NewIsNil("suite or prng pr secret key is nil")
	}

	s := &Signer[P, B, S]{
		suite: suite,
		sk:    sk,
		prng:  prng,
	}
	return s, nil
}

func (s *Signer[P, B, S]) Sign(message []byte) (*Signature[S], error) {
	digest, err := hashing.Hash(s.suite.hashFunc, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "hashing failed")
	}
	nativeSk := s.sk.ToElliptic()

	var nativeR, nativeS *big.Int

	// Use the appropriate signing method based on whether deterministic mode is enabled
	if s.prng == nil {
		// Deterministic signing (RFC 6979) using the (*PrivateKey).Sign method
		// This method requires passing the hash function as SignerOpts
		opts := signerOpts{hash: s.suite.hashFunc()}
		asn1Sig, err := nativeSk.Sign(nil, digest, opts)
		if err != nil {
			return nil, errs.WrapFailed(err, "deterministic signing failed")
		}

		// Parse ASN.1 DER-encoded signature to extract r and s
		var ecdsaSig struct {
			R, S *big.Int
		}
		_, err = asn1.Unmarshal(asn1Sig, &ecdsaSig)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to parse ASN.1 signature")
		}
		nativeR, nativeS = ecdsaSig.R, ecdsaSig.S
	} else {
		// Non-deterministic signing using the legacy Sign function
		nativeR, nativeS, err = nativeEcdsa.Sign(s.prng, nativeSk, digest)
		if err != nil {
			return nil, errs.WrapFailed(err, "signing failed")
		}
	}

	rr, err := s.suite.scalarField.FromWideBytes(nativeR.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert r")
	}
	ss, err := s.suite.scalarField.FromWideBytes(nativeS.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert s")
	}

	for i := range 5 {
		v := i
		signature, err := NewSignature(rr, ss, &v)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create signature")
		}
		recoveredPk, err := RecoverPublicKey(s.suite, signature, message)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot recover public key")
		}
		if recoveredPk.Equal(s.sk.pk) {
			return signature, nil
		}
	}

	return nil, errs.NewVerification("cannot compute recovery id")
}

func (s *Signer[P, B, S]) IsDeterministic() bool {
	return s.prng == nil
}
