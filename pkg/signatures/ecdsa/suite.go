package ecdsa

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

type Suite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve       Curve[P, B, S]
	baseField   algebra.PrimeField[B]
	scalarField algebra.PrimeField[S]
	hashFunc    func() hash.Hash
}

func NewSuite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve Curve[P, B, S], hashFunc func() hash.Hash) *Suite[P, B, S] {
	scalarField, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		panic("curve scalar field is not prime")
	}
	baseField, ok := curve.BaseStructure().(algebra.PrimeField[B])
	if !ok {
		panic("curve base field is not prime")
	}

	return &Suite[P, B, S]{
		curve,
		baseField,
		scalarField,
		hashFunc,
	}
}

func (s *Suite[P, B, S]) Curve() curves.Curve[P, B, S] {
	return s.curve
}

func (s *Suite[P, B, S]) BaseField() algebra.PrimeField[B] {
	return s.baseField
}

func (s *Suite[P, B, S]) ScalarField() algebra.PrimeField[S] {
	return s.scalarField
}

func (s *Suite[P, B, S]) HashFunc() func() hash.Hash {
	return s.hashFunc
}
