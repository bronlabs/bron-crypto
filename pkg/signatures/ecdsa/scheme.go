package ecdsa

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

type Scheme[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite *Suite[P, B, S]
	prng  io.Reader
}

func NewDeterministicScheme[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S]) (*Scheme[P, B, S], error) {
	if suite == nil {
		return nil, errs.NewIsNil("suite")
	}

	if suite.curve.Name() != p256.CurveName { // curve must be P256: https://pkg.go.dev/crypto/ecdsa#PrivateKey.Sign
		return nil, errs.NewType("unsupported curve: %s", suite.curve.Name())
	}

	s := &Scheme[P, B, S]{
		suite: suite,
		prng:  nil,
	}
	return s, nil
}

func NewScheme[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S], prng io.Reader) (*Scheme[P, B, S], error) {
	if suite == nil || prng == nil {
		return nil, errs.NewIsNil("suite or prng")
	}

	s := &Scheme[P, B, S]{
		suite: suite,
		prng:  prng,
	}
	return s, nil
}

func (s *Scheme[P, B, S]) Name() signatures.Name {
	return Name
}

func (s *Scheme[P, B, S]) IsDeterministic() bool {
	return s.prng == nil
}

func (s *Scheme[P, B, S]) Keygen(_ ...signatures.KeyGeneratorOption[*KeyGenerator[P, B, S], *PrivateKey[P, B, S], *PublicKey[P, B, S]]) (*KeyGenerator[P, B, S], error) {
	return NewKeyGenerator(s.suite.curve), nil
}

func (s *Scheme[P, B, S]) Signer(sk *PrivateKey[P, B, S], _ ...signatures.SignerOption[*Signer[P, B, S], []byte, *Signature[S]]) (*Signer[P, B, S], error) {
	var sg *Signer[P, B, S]
	var err error
	if s.IsDeterministic() {
		sg, err = NewDeterministicSigner(s.suite, sk)
	} else {
		sg, err = NewSigner(s.suite, sk, s.prng)
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "signer creation failed")
	}
	return sg, nil
}

func (s *Scheme[P, B, S]) Verifier(_ ...signatures.VerifierOption[*Verifier[P, B, S], *PublicKey[P, B, S], []byte, *Signature[S]]) (*Verifier[P, B, S], error) {
	vr, err := NewVerifier(s.suite)
	if err != nil {
		return nil, errs.WrapFailed(err, "verifier creation failed")
	}
	return vr, nil
}
