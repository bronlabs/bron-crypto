package ecdsa

import (
	"crypto"
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Suite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	deterministic bool
	curve         Curve[P, B, S]
	baseField     algebra.PrimeField[B]
	scalarField   algebra.PrimeField[S]
	hashFunc      func() hash.Hash
	hashId        crypto.Hash
}

func NewSuite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve Curve[P, B, S], hashFunc func() hash.Hash) (*Suite[P, B, S], error) {
	if hashFunc == nil {
		return nil, errs.NewIsNil("hash function")
	}
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	baseField := algebra.StructureMustBeAs[algebra.PrimeField[B]](curve.BaseStructure())

	s := &Suite[P, B, S]{
		false,
		curve,
		baseField,
		scalarField,
		hashFunc,
		0,
	}
	return s, nil
}

func NewDeterministicSuite(h crypto.Hash) (*Suite[*p256.Point, *p256.BaseFieldElement, *p256.Scalar], error) {
	if !h.Available() {
		return nil, errs.NewFailed("hash function not available")
	}

	s := &Suite[*p256.Point, *p256.BaseFieldElement, *p256.Scalar]{
		deterministic: true,
		curve:         p256.NewCurve(),
		baseField:     p256.NewBaseField(),
		scalarField:   p256.NewScalarField(),
		hashFunc:      h.New,
		hashId:        h,
	}
	return s, nil
}

func (s *Suite[P, B, S]) IsDeterministic() bool {
	return s.deterministic
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

func (s *Suite[P, B, S]) HashId() crypto.Hash {
	return s.hashId
}
