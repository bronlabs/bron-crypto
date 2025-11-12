package ecdsa

import (
	"crypto"
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

type Suite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	deterministic bool
	curve         Curve[P, B, S]
	baseField     algebra.PrimeField[B]
	scalarField   algebra.PrimeField[S]
	hashFunc      func() hash.Hash
	hashId        crypto.Hash
}

func NewSuite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], H hash.Hash](curve Curve[P, B, S], hashFunc func() H) (*Suite[P, B, S], error) {
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
		hashing.HashFuncTypeErase(hashFunc),
		0,
	}
	return s, nil
}

func NewDeterministicSuite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve Curve[P, B, S], h crypto.Hash) (*Suite[P, B, S], error) {
	if !h.Available() {
		return nil, errs.NewFailed("hash function not available")
	}
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	baseField := algebra.StructureMustBeAs[algebra.PrimeField[B]](curve.BaseStructure())

	s := &Suite[P, B, S]{
		deterministic: true,
		curve:         curve,
		baseField:     baseField,
		scalarField:   scalarField,
		hashFunc:      h.New,
		hashId:        h,
	}
	return s, nil
}

func (s *Suite[P, B, S]) IsDeterministic() bool {
	return s.deterministic
}

func (s *Suite[P, B, S]) Curve() Curve[P, B, S] {
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
