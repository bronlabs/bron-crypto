package schnorr

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"io"
	"reflect"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var fiatShamir = hashing.NewSchnorrCompatibleFiatShamir()

type PublicKey struct {
	A curves.Point

	_ types.Incomparable
}

type PrivateKey struct {
	S curves.Scalar
	PublicKey

	_ types.Incomparable
}

type Signature struct {
	R curves.Point
	S curves.Scalar

	_ types.Incomparable
}

func (s *Signature) MarshalBinary() ([]byte, error) {
	serializedSignature := bytes.Join([][]byte{s.R.ToAffineCompressed(), s.S.Bytes()}, nil)
	return serializedSignature, nil
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	serializedPublicKey := pk.A.ToAffineCompressed()
	return serializedPublicKey, nil
}

type Signer struct {
	suite      *integration.CipherSuite
	privateKey *PrivateKey
}

func NewKeys(scalar curves.Scalar) (*PublicKey, *PrivateKey, error) {
	if scalar == nil {
		return nil, nil, errs.NewIsNil("scalar is nil")
	}

	privateKey := &PrivateKey{
		S: scalar,
		PublicKey: PublicKey{
			A: scalar.Curve().ScalarBaseMult(scalar),
		},
	}

	return &privateKey.PublicKey, privateKey, nil
}

func KeyGen(curve curves.Curve, prng io.Reader) (*PublicKey, *PrivateKey, error) {
	if curve == nil {
		return nil, nil, errs.NewIsNil("curve is nil")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}

	scalar, err := curve.Scalar().Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "could not generate random scalar")
	}
	pk, sk, err := NewKeys(scalar)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate keys")
	}
	return pk, sk, nil
}

func NewSigner(suite *integration.CipherSuite, privateKey *PrivateKey) (*Signer, error) {
	if err := suite.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid cipher suite")
	}
	if privateKey == nil || privateKey.S == nil || privateKey.S.CurveName() != suite.Curve.Name() ||
		privateKey.A == nil || privateKey.A.CurveName() != suite.Curve.Name() ||
		!suite.Curve.ScalarBaseMult(privateKey.S).Equal(privateKey.A) {

		return nil, errs.NewInvalidArgument("invalid private key")
	}

	return &Signer{
		suite,
		privateKey,
	}, nil
}

func (signer *Signer) Sign(message []byte, prng io.Reader) (*Signature, error) {
	k, err := signer.suite.Curve.Scalar().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not generate random scalar")
	}
	R := signer.suite.Curve.ScalarBaseMult(k)
	a := signer.suite.Curve.ScalarBaseMult(signer.privateKey.S)

	e, err := fiatShamir.GenerateChallenge(signer.suite, R.ToAffineCompressed(), a.ToAffineCompressed(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}

	s := k.Add(signer.privateKey.S.Mul(e))
	return &Signature{
		R: R,
		S: s,
	}, nil
}

func Verify(suite *integration.CipherSuite, publicKey *PublicKey, message []byte, signature *Signature) error {
	if err := suite.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "invalid cipher suite")
	}
	if publicKey == nil || !publicKey.A.IsOnCurve() || publicKey.A.IsIdentity() || publicKey.A.CurveName() != suite.Curve.Name() {
		return errs.NewInvalidArgument("invalid signature")
	}
	if signature == nil || signature.R == nil || !signature.R.IsOnCurve() || signature.R.CurveName() != suite.Curve.Name() ||
		signature.S == nil || signature.S.CurveName() != suite.Curve.Name() {

		return errs.NewInvalidArgument("invalid signature")
	}
	// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptible
	// to a key substitution attack (specifically, it won't be bound to a public key (SBS) and a signature cannot be bound to a unique message in presence of malicious keys (MBS)).
	// Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
	if publicKey.A.IsSmallOrder() {
		return errs.NewFailed("public key is small order")
	}

	if IsEd25519Compliant(suite) {
		return verifyEd25519(publicKey, message, signature)
	}
	return verifySchnorr(suite, publicKey, message, signature)
}

func IsEd25519Compliant(suite *integration.CipherSuite) bool {
	if suite.Curve.Name() != edwards25519.Name {
		return false
	}
	if reflect.ValueOf(suite.Hash).Pointer() != reflect.ValueOf(sha512.New).Pointer() {
		return false
	}

	return true
}

func verifySchnorr(suite *integration.CipherSuite, publicKey *PublicKey, message []byte, signature *Signature) error {
	e, err := fiatShamir.GenerateChallenge(suite, signature.R.ToAffineCompressed(), publicKey.A.ToAffineCompressed(), message)
	if err != nil {
		return errs.WrapFailed(err, "cannot create challenge scalar")
	}

	cofactor := suite.Curve.Profile().Cofactor()
	left := suite.Curve.ScalarBaseMult(signature.S.Mul(cofactor))
	right := signature.R.Mul(cofactor).Add(publicKey.A.Mul(e.Mul(cofactor)))
	if !left.Equal(right) {
		return errs.NewVerificationFailed("invalid signature")
	}

	return nil
}

func verifyEd25519(publicKey *PublicKey, message []byte, signature *Signature) error {
	serializedSignature, err := signature.MarshalBinary()
	if err != nil {
		return errs.WrapSerializationError(err, "could not serialise signature to binary")
	}
	serializedPublicKey, err := publicKey.MarshalBinary()
	if err != nil {
		return errs.WrapSerializationError(err, "could not serialise signature to binary")
	}
	if ok := ed25519.Verify(serializedPublicKey, message, serializedSignature); !ok {
		return errs.NewVerificationFailed("could not verify schnorr signature using ed25519 verifier")
	}

	return nil
}
