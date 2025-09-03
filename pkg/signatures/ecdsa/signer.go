package ecdsa

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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
	// TODO: implement
	panic("not implemented")
}
