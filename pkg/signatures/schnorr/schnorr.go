package schnorr

import (
	"encoding/json"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	dlog "github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"github.com/pkg/errors"
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
		return errors.Wrapf(err, "%s couldn't extract C and S field from input", errs.DeserializationFailed)
	}

	s.C, err = curves.Curve{}.NewScalarFromJSON(parsed.C)
	if err != nil {
		return errors.Wrapf(err, "%s couldn't deserialize C", errs.DeserializationFailed)
	}
	s.S, err = curves.Curve{}.NewScalarFromJSON(parsed.S)
	if err != nil {
		return errors.Wrapf(err, "%s couldn't deserialize S", errs.DeserializationFailed)
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
		return nil, errors.Wrapf(err, "%s ciphersuite is invalid", errs.InvalidArgument)
	}
	privateKey, err := KeyGen(cipherSuite.Curve, secret, prng)
	if err != nil {
		return nil, errors.Wrapf(err, "%s key generation failed", errs.Failed)
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
		return nil, errors.Wrapf(err, "%s could not construct an internal prover", errs.Failed)
	}
	proof, err := prover.Prove(s.privateKey.a)
	if err != nil {
		return nil, errors.Wrapf(err, "%s couldn't make proof of knowledge of discrete log of public key bound with the message", errs.Failed)
	}
	return &Signature{
		C: proof.C,
		S: proof.S,
	}, nil
}

func KeyGen(curve *curves.Curve, secret curves.Scalar, prng io.Reader) (*PrivateKey, error) {
	if curve == nil {
		return nil, errors.Errorf("%s curve is nil", errs.IsNil)
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
		return errors.Wrapf(err, "%s ciphersuite is invalid", errs.InvalidArgument)
	}
	if publicKey == nil {
		return errors.Errorf("%s public key is not provided", errs.IsNil)
	}
	if !publicKey.Y.IsOnCurve() {
		return errors.Errorf("%s public key is not on curve", errs.NotOnCurve)
	}
	if publicKey.Y.IsIdentity() {
		return errors.Errorf("%s public key can't be at infinity", errs.IsIdentity)
	}

	if cipherSuite.Curve.Name == curves.ED25519Name {
		edwardsPoint, ok := publicKey.Y.(*curves.PointEd25519)
		if !ok {
			return errors.New("curve is ed25519 but the public key could not be type casted to the correct point struct")
		}
		if edwardsPoint.IsSmallOrder() {
			return errors.New("public key is small order")
		}
	}

	if signature.C.IsZero() {
		return errors.Errorf("%s challenge can't be zero", errs.IsZero)
	}
	if signature.S.IsZero() {
		return errors.Errorf("%s response can't be zero", errs.IsZero)
	}
	proof := &dlog.Proof{
		C:         signature.C,
		S:         signature.S,
		Statement: publicKey.Y,
	}

	if err := dlog.Verify(cipherSuite.Curve.Point.Generator(), proof, message, nil); err != nil {
		return errors.Wrapf(err, "%s couldn't verify underlying schnor proof", errs.VerificationFailed)
	}
	return nil
}
