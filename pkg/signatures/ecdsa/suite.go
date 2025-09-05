package ecdsa

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Suite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve       Curve[P, B, S]
	baseField   algebra.PrimeField[B]
	scalarField algebra.PrimeField[S]
	hashFunc    func() hash.Hash
}

func NewSuite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve Curve[P, B, S], hashFunc func() hash.Hash) (*Suite[P, B, S], error) {
	if hashFunc == nil {
		return nil, errs.NewIsNil("hash function")
	}
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	baseField := algebra.StructureMustBeAs[algebra.PrimeField[B]](curve.BaseStructure())

	s := &Suite[P, B, S]{
		curve,
		baseField,
		scalarField,
		hashFunc,
	}
	return s, nil
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
