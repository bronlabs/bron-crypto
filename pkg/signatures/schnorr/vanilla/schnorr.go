package schnorr

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"io"
)

type PublicKey[C curves.CurveIdentifier] struct {
	A curves.Point[C]

	_ types.Incomparable
}

type PrivateKey[C curves.CurveIdentifier] struct {
	S curves.Scalar[C]
	PublicKey[C]

	_ types.Incomparable
}

type Signature[C curves.CurveIdentifier] struct {
	R curves.Point[C]
	S curves.Scalar[C]

	_ types.Incomparable
}

func (s *Signature[C]) MarshalBinary() ([]byte, error) {
	serializedSignature := bytes.Join([][]byte{s.R.ToAffineCompressed(), s.S.Bytes()}, nil)
	return serializedSignature, nil
}

func (pk *PublicKey[C]) MarshalBinary() ([]byte, error) {
	serializedPublicKey := pk.A.ToAffineCompressed()
	return serializedPublicKey, nil
}

type Signer[C curves.CurveIdentifier] struct {
	privateKey *PrivateKey[C]
}

func NewKeys[C curves.CurveIdentifier](scalar curves.Scalar[C]) (*PublicKey[C], *PrivateKey[C], error) {
	if scalar == nil {
		return nil, nil, errs.NewIsNil("scalar is nil")
	}

	privateKey := &PrivateKey[C]{
		S: scalar,
		PublicKey: PublicKey[C]{
			A: scalar.Curve().ScalarBaseMult(scalar),
		},
	}

	return &privateKey.PublicKey, privateKey, nil
}

func KeyGen[C curves.CurveIdentifier](curve curves.Curve[C], prng io.Reader) (*PublicKey[C], *PrivateKey[C], error) {
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

func NewSigner[C curves.CurveIdentifier](privateKey *PrivateKey[C]) (*Signer[C], error) {
	if privateKey == nil || privateKey.S == nil || privateKey.A == nil ||
		!privateKey.S.Curve().Generator().Mul(privateKey.S).Equal(privateKey.PublicKey.A) {

		return nil, errs.NewInvalidArgument("invalid private key")
	}

	return &Signer[C]{
		privateKey,
	}, nil
}

func (signer *Signer[C]) Sign(message []byte, prng io.Reader) (*Signature[C], error) {
	curve := signer.privateKey.S.Curve()
	k, err := curve.Scalar().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not generate random scalar")
	}
	R := curve.ScalarBaseMult(k)
	a := curve.ScalarBaseMult(signer.privateKey.S)

	e, err := generateChallenge(curve, R.ToAffineCompressed(), a.ToAffineCompressed(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}

	s := k.Add(signer.privateKey.S.Mul(e))
	return &Signature[C]{
		R: R,
		S: s,
	}, nil
}

func Verify[C curves.CurveIdentifier](publicKey *PublicKey[C], message []byte, signature *Signature[C]) error {
	if publicKey == nil || !publicKey.A.IsOnCurve() || publicKey.A.IsIdentity() {
		return errs.NewInvalidArgument("invalid signature")
	}
	if signature == nil || signature.R == nil || !signature.R.IsOnCurve() || signature.S == nil {
		return errs.NewInvalidArgument("invalid signature")
	}
	// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptible
	// to a key substitution attack (specifically, it won't be bound to a public key (SBS) and a signature cannot be bound to a unique message in presence of malicious keys (MBS)).
	// Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
	if publicKey.A.IsSmallOrder() {
		return errs.NewFailed("public key is small order")
	}

	if IsEd25519Compliant(publicKey.A.Curve()) {
		return verifyEd25519(publicKey, message, signature)
	}
	return verifySchnorr(publicKey, message, signature)
}

func IsEd25519Compliant[C curves.CurveIdentifier](curve curves.Curve[C]) bool {
	if curve.Name() != edwards25519.Name {
		return false
	}

	return true
}

func verifySchnorr[C curves.CurveIdentifier](publicKey *PublicKey[C], message []byte, signature *Signature[C]) error {
	curve := publicKey.A.Curve()
	e, err := generateChallenge(publicKey.A.Curve(), signature.R.ToAffineCompressed(), publicKey.A.ToAffineCompressed(), message)
	if err != nil {
		return errs.WrapFailed(err, "cannot create challenge scalar")
	}

	cofactor := curve.Profile().Cofactor()
	left := curve.ScalarBaseMult(signature.S.Mul(cofactor))
	right := signature.R.Mul(cofactor).Add(publicKey.A.Mul(e.Mul(cofactor)))
	if !left.Equal(right) {
		return errs.NewVerificationFailed("invalid signature")
	}

	return nil
}

func verifyEd25519[C curves.CurveIdentifier](publicKey *PublicKey[C], message []byte, signature *Signature[C]) error {
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

// dummy
func generateChallenge[C curves.CurveIdentifier](curve curves.Curve[C], bytes ...[]byte) (curves.Scalar[C], error) {
	// do whatever it takes
	return curve.Scalar().Random(crand.Reader)
}
