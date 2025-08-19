package ecdsa

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type Suite[P algebra.PrimeOrderEllipticCurvePoint[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve    algebra.PrimeOrderEllipticCurve[P, B, S]
	field    algebra.PrimeField[S]
	hashFunc func() hash.Hash
}

func NewSuite[P algebra.PrimeOrderEllipticCurvePoint[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](curve algebra.PrimeOrderEllipticCurve[P, B, S], hashFunc func() hash.Hash) *Suite[P, B, S] {
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

func (s *Suite[P, B, S]) Curve() algebra.PrimeOrderEllipticCurve[P, B, S] {
	return s.curve
}

func (s *Suite[P, B, S]) ScalarField() algebra.PrimeField[S] {
	return s.field
}

func (s *Suite[P, B, S]) HashFunc() func() hash.Hash {
	return s.hashFunc
}
