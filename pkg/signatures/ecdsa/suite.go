package ecdsa

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

type Suite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve    curves.Curve[P, B, S]
	field    algebra.PrimeField[S]
	hashFunc func() hash.Hash
}

func NewSuite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S], hashFunc func() hash.Hash) *Suite[P, B, S] {
	field, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		panic("curve scalar field is not prime")
	}

	return &Suite[P, B, S]{
		curve,
		field,
		hashFunc,
	}
}

func (s *Suite[P, B, S]) Curve() curves.Curve[P, B, S] {
	return s.curve
}

func (s *Suite[P, B, S]) ScalarField() algebra.PrimeField[S] {
	return s.field
}

func (s *Suite[P, B, S]) HashFunc() func() hash.Hash {
	return s.hashFunc
}
