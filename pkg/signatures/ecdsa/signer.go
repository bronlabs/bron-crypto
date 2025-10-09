package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

type Signer[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite *Suite[P, B, S]
	sk    *PrivateKey[P, B, S]
	prng  io.Reader
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
	nativeR, nativeS, err := nativeEcdsa.Sign(s.prng, nativeSk, digest)
	if err != nil {
		return nil, errs.WrapFailed(err, "signing failed")
	}
	rr, err := s.suite.scalarField.FromWideBytes(nativeR.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert r")
	}
	ss, err := s.suite.scalarField.FromWideBytes(nativeS.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert s")
	}

	for i := 0; i <= 4; i++ {
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
