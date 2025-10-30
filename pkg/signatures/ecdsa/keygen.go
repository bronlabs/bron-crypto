package ecdsa

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type KeyGenerator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve       Curve[P, B, S]
	scalarField algebra.PrimeField[S]
}

func NewKeyGenerator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve Curve[P, B, S]) *KeyGenerator[P, B, S] {
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	kg := &KeyGenerator[P, B, S]{
		curve:       curve,
		scalarField: scalarField,
	}
	return kg
}

func (kg *KeyGenerator[P, B, S]) Generate(prng io.Reader) (*PrivateKey[P, B, S], *PublicKey[P, B, S], error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	skRaw, err := kg.scalarField.Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample private key")
	}
	pkRaw := kg.curve.ScalarBaseMul(skRaw)

	pk, err := NewPublicKey(pkRaw)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create public key")
	}
	sk, err := NewPrivateKey(skRaw.Clone(), pk.Clone())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create secret key")
	}
	return sk, pk, nil
}
