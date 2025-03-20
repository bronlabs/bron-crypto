package vanilla

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"hash"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

type PublicKey[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] schnorr.PublicKey[P, B, S]

type PrivateKey[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] schnorr.PrivateKey[P, B, S]

type Signature[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] = schnorr.Signature[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S]

func (pk *PublicKey[P, B, S]) MarshalBinary() ([]byte, error) {
	serializedPublicKey := pk.A.ToAffineCompressed()
	return serializedPublicKey, nil
}

type Signer[C curves.Curve[P, B, S], P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
	curve      C
	hashFunc   func() hash.Hash
	privateKey *PrivateKey[P, B, S]
}

func KeyGen[C curves.Curve[P, B, S], P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]](curve C, prng io.Reader) (*PublicKey[P, B, S], *PrivateKey[P, B, S], error) {
	if curve == nil {
		return nil, nil, errs.NewIsNil("curve is nil")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}

	// TODO(aalireza) add method to get scalar field from curve
	scalarField, err := fields.GetPrimeField(*new(S))
	if err != nil {
		return nil, nil, errs.NewIsNil("scalarField is nil")
	}
	scalar, err := scalarField.Random(prng)
	if err != nil {
		return nil, nil, errs.NewIsNil("scalar is nil")
	}
	point := curve.Generator().ScalarMul(scalar)

	sk := &PrivateKey[P, B, S]{
		S: scalar,
	}
	pk := &PublicKey[P, B, S]{
		A: point,
	}
}

func NewSigner[C curves.Curve[P, B, S], P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]](curve C, hashFunc func() hash.Hash, privateKey *PrivateKey[P, B, S]) (*Signer[C, P, B, S], error) {
	return &Signer[C, P, B, S]{
		curve:      curve,
		hashFunc:   hashFunc,
		privateKey: privateKey,
	}, nil
}

func (signer *Signer[C, P, B, S]) Sign(message []byte, prng io.Reader) (*Signature[P, B, S], error) {
	// TODO(aalireza) add method to get scalar field from curve
	scalarField, err := fields.GetPrimeField(*new(S))
	if err != nil {
		return nil, errs.NewIsNil("scalarField is nil")
	}
	k, err := scalarField.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random scalar")
	}
	R := signer.curve.Generator().ScalarMul(k)
	a := signer.curve.Generator().ScalarMul(signer.privateKey.S)

	variant := NewEdDsaCompatibleVariant(signer.curve)
	e, err := variant.ComputeChallenge(signer.suite, R, a, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}

	s := variant.ComputeResponse(R, a, k, signer.privateKey.S, e)
	return schnorr.NewSignature(variant, e, variant.ComputeNonceCommitment(R, R), s), nil
}

func Verify[C curves.Curve[P, B, S], P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]](curve C, hashFunc func() hash.Hash, publicKey *PublicKey[P, B, S], message []byte, signature *Signature[P, B, S]) error {
	variant := NewEdDsaCompatibleVariant(curve)
	v, err := variant.NewVerifierBuilder().
		WithSigningSuite(suite).
		WithPublicKey((*schnorr.PublicKey[P, B, S])(publicKey)).
		WithMessage(message).
		Build()
	if err != nil {
		return errs.WrapFailed(err, "could not build the verifier")
	}

	//nolint:wrapcheck // forward errors
	return v.Verify(signature)
}
