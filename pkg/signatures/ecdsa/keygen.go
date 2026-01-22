package ecdsa

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// KeyGenerator generates ECDSA key pairs by sampling random scalars from the
// curve's scalar field and computing the corresponding public keys.
type KeyGenerator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve       Curve[P, B, S]
	scalarField algebra.PrimeField[S]
}

// NewKeyGenerator creates a key generator for the specified elliptic curve.
func NewKeyGenerator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve Curve[P, B, S]) *KeyGenerator[P, B, S] {
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	kg := &KeyGenerator[P, B, S]{
		curve:       curve,
		scalarField: scalarField,
	}
	return kg
}

// Generate creates a new ECDSA key pair using random bytes from the provided reader.
//
// The private key d is sampled uniformly from [1, n-1] where n is the curve order.
// The public key Q is computed as Q = d * G where G is the curve's generator.
//
// The prng must be a cryptographically secure random source (e.g., crypto/rand.Reader).
func (kg *KeyGenerator[P, B, S]) Generate(prng io.Reader) (*PrivateKey[P, B, S], *PublicKey[P, B, S], error) {
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("prng is nil")
	}
	skRaw, err := kg.scalarField.Random(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample private key")
	}
	pkRaw := kg.curve.ScalarBaseMul(skRaw)

	pk, err := NewPublicKey(pkRaw)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create public key")
	}
	sk, err := NewPrivateKey(skRaw.Clone(), pk.Clone())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create secret key")
	}
	return sk, pk, nil
}
