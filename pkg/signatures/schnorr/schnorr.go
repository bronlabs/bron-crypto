package schnorr

import (
	"encoding/json"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	dlog "github.com/copperexchange/knox-primitives/pkg/proofs/dlog/schnorr"
)

type PrivateKey struct {
	a curves.Scalar
	PublicKey
}

type PublicKey struct {
	Curve *curves.Curve
	Y     curves.Point
}

type Signature struct {
	C curves.Scalar
	S curves.Scalar
}

func (s *Signature) UnmarshalJSON(data []byte) error {
	var err error
	var parsed struct {
		C json.RawMessage
		S json.RawMessage
	}

	if err := json.Unmarshal(data, &parsed); err != nil {
		return errs.WrapDeserializationFailed(err, "couldn't extract C and S field from input")
	}

	s.C, err = curves.Curve{}.NewScalarFromJSON(parsed.C)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "couldn't deserialize C")
	}
	s.S, err = curves.Curve{}.NewScalarFromJSON(parsed.S)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "couldn't deserialize S")
	}
	return nil
}

type Signer struct {
	CipherSuite *integration.CipherSuite
	PublicKey   *PublicKey
	privateKey  *PrivateKey
	prng        io.Reader
	options     *Options
}

type Options struct {
	TranscriptPrefixes [][]byte
	TranscriptSuffixes [][]byte
}

func NewSigner(cipherSuite *integration.CipherSuite, secret curves.Scalar, prng io.Reader, options *Options) (*Signer, error) {
	if err := cipherSuite.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "ciphersuite is invalid")
	}
	privateKey, err := KeyGen(cipherSuite.Curve, secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "key generation failed")
	}

	return &Signer{
		CipherSuite: cipherSuite,
		PublicKey:   &privateKey.PublicKey,
		privateKey:  privateKey,
		prng:        prng,
		options:     options,
	}, nil
}

func (s *Signer) Sign(message []byte) (*Signature, error) {
	prover, err := dlog.NewProver(s.CipherSuite.Curve.Point.Generator(), message, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct an internal prover")
	}
	proof, _, err := prover.Prove(s.privateKey.a)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't make proof of knowledge of discrete log of public key bound with the message")
	}
	return &Signature{
		C: proof.C,
		S: proof.S,
	}, nil
}

func KeyGen(curve *curves.Curve, secret curves.Scalar, prng io.Reader) (*PrivateKey, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if secret == nil {
		secret = curve.Scalar.Random(prng)
	}
	publicKey := curve.ScalarBaseMult(secret)

	return &PrivateKey{
		a: secret,
		PublicKey: PublicKey{
			Curve: curve,
			Y:     publicKey,
		},
	}, nil
}

func Verify(cipherSuite *integration.CipherSuite, publicKey *PublicKey, message []byte, signature *Signature, options *Options) error {
	if err := cipherSuite.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "ciphersuite is invalid")
	}
	if publicKey == nil {
		return errs.NewIsNil("public key is not provided")
	}
	if !publicKey.Y.IsOnCurve() {
		return errs.NewNotOnCurve("public key is not on curve")
	}
	if publicKey.Y.IsIdentity() {
		return errs.NewIsIdentity("public key can't be at infinity")
	}

	if cipherSuite.Curve.Name == curves.ED25519Name {
		edwardsPoint, ok := publicKey.Y.(*curves.PointEd25519)
		if !ok {
			return errs.NewDeserializationFailed("curve is ed25519 but the public key could not be type casted to the correct point struct")
		}
		if edwardsPoint.IsSmallOrder() {
			return errs.NewFailed("public key is small order")
		}
	}

	if signature.C.IsZero() {
		return errs.NewIsZero("challenge can't be zero")
	}
	if signature.S.IsZero() {
		return errs.NewIsZero("response can't be zero")
	}
	proof := &dlog.Proof{
		C: signature.C,
		S: signature.S,
	}

	if err := dlog.Verify(cipherSuite.Curve.Point.Generator(), publicKey.Y, proof, message, nil); err != nil {
		return errs.NewVerificationFailed("couldn't verify underlying schnor proof")
	}
	return nil
}
