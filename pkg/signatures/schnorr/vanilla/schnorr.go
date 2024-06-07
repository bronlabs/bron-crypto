package vanilla

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
)

type PublicKey schnorr.PublicKey

type PrivateKey schnorr.PrivateKey

type Signature = schnorr.Signature[EdDsaCompatibleVariant]

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	serializedPublicKey := pk.A.ToAffineCompressed()
	return serializedPublicKey, nil
}

type Signer struct {
	suite      types.SigningSuite
	privateKey *PrivateKey
}

func NewKeys(scalar curves.Scalar) (*PublicKey, *PrivateKey, error) {
	if scalar == nil {
		return nil, nil, errs.NewIsNil("scalar is nil")
	}

	privateKey := &schnorr.PrivateKey{
		S: scalar,
		PublicKey: schnorr.PublicKey{
			A: scalar.ScalarField().Curve().ScalarBaseMult(scalar),
		},
	}

	return (*PublicKey)(&privateKey.PublicKey), (*PrivateKey)(privateKey), nil
}

func KeyGen(curve curves.Curve, prng io.Reader) (*PublicKey, *PrivateKey, error) {
	if curve == nil {
		return nil, nil, errs.NewIsNil("curve is nil")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}

	scalar, err := curve.ScalarField().Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not generate random scalar")
	}
	pk, sk, err := NewKeys(scalar)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate keys")
	}
	return pk, sk, nil
}

func NewSigner(suite types.SigningSuite, privateKey *PrivateKey) (*Signer, error) {
	if err := types.ValidateSigningSuite(suite); err != nil {
		return nil, errs.WrapArgument(err, "invalid cipher suite")
	}
	if privateKey == nil || privateKey.S == nil || privateKey.S.ScalarField().Name() != suite.Curve().Name() ||
		privateKey.A == nil || privateKey.A.Curve().Name() != suite.Curve().Name() ||
		!suite.Curve().ScalarBaseMult(privateKey.S).Equal(privateKey.A) {

		return nil, errs.NewArgument("invalid private key")
	}

	return &Signer{
		suite,
		privateKey,
	}, nil
}

func (signer *Signer) Sign(message []byte, prng io.Reader) (*Signature, error) {
	k, err := signer.suite.Curve().ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random scalar")
	}
	R := signer.suite.Curve().ScalarBaseMult(k)
	a := signer.suite.Curve().ScalarBaseMult(signer.privateKey.S)

	eBytes := edDsaCompatibleVariant.ComputeChallengeBytes(R, a, message)
	e, err := schnorr.MakeGenericSchnorrChallenge(signer.suite, eBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}

	s := edDsaCompatibleVariant.ComputeResponse(R, a, k, signer.privateKey.S, e)
	return schnorr.NewSignature(edDsaCompatibleVariant, e, edDsaCompatibleVariant.ComputeNonceCommitment(R, R), s), nil
}

func Verify(suite types.SigningSuite, publicKey *PublicKey, message []byte, signature *Signature) error {
	v := edDsaCompatibleVariant.NewVerifierBuilder().
		WithSigningSuite(suite).
		WithPublicKey((*schnorr.PublicKey)(publicKey)).
		WithMessage(message).
		Build()

	//nolint:wrapcheck // forward errors
	return v.Verify(signature)
}
