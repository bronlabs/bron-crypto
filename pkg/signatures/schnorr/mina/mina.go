package mina

import (
	"encoding"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

var (
	_ encoding.BinaryMarshaler = (*PublicKey)(nil)

	curve     = pasta.NewPallasCurve()
	curveName = curve.Name()
	suite, _  = types.NewSigningSuite(pasta.NewPallasCurve(), poseidon.NewLegacyHash)
)

type PublicKey schnorr.PublicKey

type PrivateKey struct {
	S curves.Scalar
	PublicKey

	_ ds.Incomparable
}

type Signature = schnorr.Signature[MinaVariant, *ROInput]

type Signer struct {
	privateKey *PrivateKey
	networkId  NetworkId

	_ ds.Incomparable
}

func NewPrivateKey(scalar curves.Scalar) (*PrivateKey, error) {
	if scalar == nil {
		return nil, errs.NewIsNil("secret is nil")
	}

	sk := &PrivateKey{
		S: scalar,
		PublicKey: PublicKey{
			A: curve.ScalarBaseMult(scalar),
		},
	}
	return sk, nil
}

func KeyGen(prng io.Reader) (*PrivateKey, *PublicKey, error) {
	scalar, err := curve.ScalarField().Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}
	sk, err := NewPrivateKey(scalar)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create secret key")
	}

	return sk, &sk.PublicKey, nil
}

func NewSigner(privateKey *PrivateKey, networkId NetworkId) (*Signer, error) {
	if privateKey == nil {
		return nil, errs.NewIsNil("private key")
	}

	return &Signer{
		privateKey: privateKey,
		networkId:  networkId,
	}, nil
}

func (signer *Signer) Sign(message *ROInput, prng io.Reader) (*Signature, error) {
	variant := NewMinaVariant(signer.networkId)
	publicKey := curve.ScalarBaseMult(signer.privateKey.S)

	// TODO: implement "deriveNonceLegacy, for now sample randomly"
	kPrime, err := curve.ScalarField().Random(prng)
	if err != nil {
		return nil, errs.NewFailed("cannot set k'")
	}
	if kPrime.IsZero() {
		return nil, errs.NewFailed("k' is invalid")
	}
	bigR := curve.ScalarBaseMult(kPrime)

	e, err := variant.ComputeChallenge(suite, bigR, publicKey, message)
	if err != nil {
		return nil, errs.NewFailed("cannot compute challenge")
	}

	r := variant.ComputeNonceCommitment(bigR, bigR)
	s := variant.ComputeResponse(bigR, publicKey, kPrime, signer.privateKey.S, e)

	return schnorr.NewSignature(variant, nil, r, s), nil
}

func Verify(publicKey *PublicKey, signature *Signature, message *ROInput, networkId NetworkId) error {
	minaVariant := NewMinaVariant(networkId)
	verifier, err := minaVariant.NewVerifierBuilder().
		WithPublicKey((*schnorr.PublicKey)(publicKey)).
		WithMessage(message).
		Build()
	if err != nil {
		return errs.WrapFailed(err, "could not build the verifier")
	}

	//nolint:wrapcheck // forward errors
	return verifier.Verify(signature)
}

func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	return pk.A.ToAffineCompressed(), nil
}
