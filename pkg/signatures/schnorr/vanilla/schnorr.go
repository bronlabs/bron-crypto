package schnorr

import (
	"crypto/ed25519"
	"crypto/sha512"
	"io"
	"reflect"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
)

type PublicKey struct {
	A curves.Point

	_ ds.Incomparable
}

type PrivateKey struct {
	S curves.Scalar
	PublicKey

	_ ds.Incomparable
}

type Signature = schnorr.Signature[schnorr.EdDsaCompatibleVariant]

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

	privateKey := &PrivateKey{
		S: scalar,
		PublicKey: PublicKey{
			A: scalar.ScalarField().Curve().ScalarBaseMult(scalar),
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

	e, err := MakeSchnorrCompatibleChallenge(signer.suite, R.ToAffineCompressed(), a.ToAffineCompressed(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}

	s := k.Add(signer.privateKey.S.Mul(e))
	return schnorr.NewSignature(schnorr.NewEdDsaCompatibleVariant(), e, R, s), nil
}

func Verify(suite types.SigningSuite, publicKey *PublicKey, message []byte, signature *Signature) error {
	if err := types.ValidateSigningSuite(suite); err != nil {
		return errs.WrapArgument(err, "invalid cipher suite")
	}
	if publicKey == nil || publicKey.A.IsIdentity() || publicKey.A.Curve().Name() != suite.Curve().Name() {
		return errs.NewArgument("invalid signature")
	}
	if signature == nil || signature.R == nil || signature.R.Curve().Name() != suite.Curve().Name() ||
		signature.S == nil || signature.S.ScalarField().Name() != suite.Curve().Name() {

		return errs.NewArgument("invalid signature")
	}
	// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptible
	// to a key substitution attack (specifically, it won't be bound to a public key (SBS) and a signature cannot be bound to a unique message in presence of malicious keys (MBS)).
	// Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
	if publicKey.A.IsSmallOrder() {
		return errs.NewFailed("public key is small order")
	}

	if IsEd25519Compliant(suite) {
		return verifyNativeEd25519(publicKey, message, signature)
	}
	return verifySchnorr(suite, publicKey, message, signature)
}

func IsEd25519Compliant(suite types.SigningSuite) bool {
	return (suite.Curve().Name() == edwards25519.Name) && (reflect.ValueOf(suite.Hash()).Pointer() == reflect.ValueOf(sha512.New).Pointer())
}

func verifySchnorr(suite types.SigningSuite, publicKey *PublicKey, message []byte, signature *Signature) error {
	e, err := MakeSchnorrCompatibleChallenge(suite, signature.R.ToAffineCompressed(), publicKey.A.ToAffineCompressed(), message)
	if err != nil {
		return errs.WrapFailed(err, "cannot create challenge scalar")
	}
	if signature.E != nil && !signature.E.Equal(e) {
		return errs.NewFailed("incompatible schnorr signature")
	}

	cofactorNat := suite.Curve().Cofactor()
	cofactor := suite.Curve().ScalarField().Element().SetNat(cofactorNat)
	left := suite.Curve().ScalarBaseMult(signature.S.Mul(cofactor))
	right := signature.R.Mul(cofactor).Add(publicKey.A.Mul(e.Mul(cofactor)))
	if !left.Equal(right) {
		return errs.NewVerification("invalid signature")
	}

	return nil
}

func verifyNativeEd25519(publicKey *PublicKey, message []byte, signature *Signature) error {
	serializedSignature := slices.Concat(signature.R.ToAffineCompressed(), bitstring.ReverseBytes(signature.S.Bytes()))
	serializedPublicKey, err := publicKey.MarshalBinary()
	if err != nil {
		return errs.WrapSerialisation(err, "could not serialise signature to binary")
	}
	if ok := ed25519.Verify(serializedPublicKey, message, serializedSignature); !ok {
		return errs.NewVerification("could not verify schnorr signature using ed25519 verifier")
	}

	return nil
}

func MakeSchnorrCompatibleChallenge(suite types.SigningSuite, xs ...[]byte) (curves.Scalar, error) {
	for _, x := range xs {
		if x == nil {
			return nil, errs.NewIsNil("an input is nil")
		}
	}

	digest, err := hashing.Hash(suite.Hash(), xs...)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not compute fiat shamir hash")
	}

	var challenge curves.Scalar
	// In EdDSA, the digest is treated and passed as little endian, however for consistency, all our curves' inputs are big endian.
	if IsEd25519Compliant(suite) {
		challenge, err = edwards25519.NewScalar(0).SetBytesWideLE(digest)
	} else {
		challenge, err = suite.Curve().Scalar().SetBytesWide(digest)
	}
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not compute fiat shamir challenge")
	}
	return challenge, nil
}
