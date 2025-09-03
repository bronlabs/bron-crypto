package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

type Verifier[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite *Suite[P, B, S]
}

func NewVerifier[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *Suite[P, B, S]) (*Verifier[P, B, S], error) {
	if suite == nil {
		return nil, errs.NewIsNil("suite")
	}

	v := &Verifier[P, B, S]{
		suite: suite,
	}
	return v, nil
}

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
