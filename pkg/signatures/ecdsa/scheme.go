package ecdsa

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

// Scheme represents a configured ECDSA signature scheme instance.
// It binds a cryptographic Suite with a random source and provides factory methods
// for creating key generators, signers, and verifiers.
type Scheme[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite *Suite[P, B, S]
	prng  io.Reader
}

// NewScheme creates a new ECDSA scheme from a suite and random source.
//
// For randomised ECDSA suites, prng must be a cryptographically secure random source
// (e.g., crypto/rand.Reader). For deterministic suites (RFC 6979), prng can be nil
// as the nonce is derived from the private key and message.
func NewScheme[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S], prng io.Reader) (*Scheme[P, B, S], error) {
	if suite == nil || (!suite.IsDeterministic() && prng == nil) {
		return nil, ErrInvalidArgument.WithMessage("suite or prng is nil")
	}

	s := &Scheme[P, B, S]{
		suite: suite,
		prng:  prng,
	}
	return s, nil
}

// Name returns the signature scheme identifier ("ECDSA").
func (*Scheme[P, B, S]) Name() signatures.Name {
	return Name
}

// Keygen creates a key generator for producing ECDSA key pairs.
func (s *Scheme[P, B, S]) Keygen(_ ...signatures.KeyGeneratorOption[*KeyGenerator[P, B, S], *PrivateKey[P, B, S], *PublicKey[P, B, S]]) (*KeyGenerator[P, B, S], error) {
	return NewKeyGenerator(s.suite.curve), nil
}

// Signer creates a signer for producing ECDSA signatures with the given private key.
func (s *Scheme[P, B, S]) Signer(sk *PrivateKey[P, B, S], _ ...signatures.SignerOption[*Signer[P, B, S], []byte, *Signature[S]]) (*Signer[P, B, S], error) {
	sg, err := NewSigner(s.suite, sk, s.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("signer creation failed")
	}
	return sg, nil
}

// Verifier creates a verifier for validating ECDSA signatures.
func (s *Scheme[P, B, S]) Verifier(_ ...signatures.VerifierOption[*Verifier[P, B, S], *PublicKey[P, B, S], []byte, *Signature[S]]) (*Verifier[P, B, S], error) {
	vr, err := NewVerifier(s.suite)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("verifier creation failed")
	}
	return vr, nil
}

// Suite returns the cryptographic suite used by this scheme.
func (s *Scheme[P, B, S]) Suite() *Suite[P, B, S] {
	return s.suite
}
