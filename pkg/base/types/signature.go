package types

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

type SigningSuite[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] interface {
	Curve() C
	Hash() func() hash.Hash
}

func NewSigningSuite[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](curve C, hashFunc func() hash.Hash) (SigningSuite[C, P, F, S], error) {
	protocol := &protocol[C, P, F, S]{
		curve: curve,
		hash:  hashFunc,
	}

	return protocol, nil
}
