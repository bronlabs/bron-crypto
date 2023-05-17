package schnorr

import (
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

// func (s *Signature) MarshalJSON() ([]byte, error) {
// 	wrapper := &struct {
// 		Curve     string
// 		Signature *Signature
// 	}{
// 		Curve:     s.C.Point().CurveName(),
// 		Signature: s,
// 	}
// 	output, err := json.Marshal(wrapper)
// 	if err != nil {
// 		return nil, errors.Wrap(err, "could not marshal signature")
// 	}
// 	return output, nil
// }

// func (s *Signature) UnmarshalJSON(data []byte) error {
// 	curveName := struct{
// 		Curve string
// 	}{}
// 	if err := json.Unmarshal(data, curveName); err != nil {
// 		return errors.Wrap(err, "could not unmarshal the curve name")
// 	}
// 	if len(curveName.Curve) == 0 {
// 		return errors.New("curve name is empty")
// 	}
// 	curve := curves.GetCurveByName(curveName.Curve)
// 	if curve == nil {
// 		return errors.Errorf("could not find curve with the specified name: %s", curveName.Curve)
// 	}
// 	// curve.
// 	// unmarshaled := map[string]*curves.ScalarK256{}
// 	// if err := json.Unmarshal(data, &unmarshaled); err != nil {
// 	// 	return errors.Wrap(err, "could not unmarshal signature")
// 	// }

// 	unmarshaled, err := curves.ScalarUnmarshalJson(data)
// 	if err != nil {
// 		return errors.Wrap(err, "could not unmarshal into scalar")
// 	}

// 	s = &unmarshaled

// 	// s.C = unmarshaled["C"]
// 	// s.S = unmarshaled["S"]

// 	return nil
// }

type Signer struct {
	CipherSuite *integration.CipherSuite
	PublicKey   *PublicKey
	privateKey  *PrivateKey
	reader      io.Reader
	options     *Options
}

type Options struct {
	TranscriptPrefixes [][]byte
	TranscriptSuffixes [][]byte
}

func NewSigner(cipherSuite *integration.CipherSuite, secret curves.Scalar, reader io.Reader, options *Options) (*Signer, error) {
	if err := cipherSuite.Validate(); err != nil {
		return nil, errors.Wrap(err, "ciphersuite is invalid")
	}
	privateKey, err := KeyGen(cipherSuite.Curve, secret, reader)
	if err != nil {
		return nil, errors.Wrap(err, "key generation failed")
	}

	return &Signer{
		CipherSuite: cipherSuite,
		PublicKey:   &privateKey.PublicKey,
		privateKey:  privateKey,
		reader:      reader,
		options:     options,
	}, nil
}

func (s *Signer) Sign(message []byte) (*Signature, error) {
	prover, err := dlog.NewProver(s.CipherSuite.Curve.Point.Generator(), message, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not consturct an internal prover")
	}
	proof, err := prover.Prove(s.privateKey.a)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't make proof of knowledge of discrete log of public key bound with the message")
	}
	return &Signature{
		C: proof.C,
		S: proof.S,
	}, nil
}

func KeyGen(curve *curves.Curve, secret curves.Scalar, reader io.Reader) (*PrivateKey, error) {
	if curve == nil {
		return nil, errors.New("curve is nil")
	}
	// if curve.Name != curves.K256Name && curve.Name != P256
	if secret == nil {
		secret = curve.Scalar.Random(reader)
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
		return errors.Wrap(err, "ciphersuite is invalid")
	}
	if publicKey == nil {
		return errors.New("public key is not provided")
	}
	if !publicKey.Y.IsOnCurve() {
		return errors.New("public key is not on curve")
	}
	if publicKey.Y.IsIdentity() {
		return errors.New("public key can't be at infinity")
	}
	if signature.C.IsZero() {
		return errors.New("challenge can't be zero")
	}
	if signature.S.IsZero() {
		return errors.New("response can't be zero")
	}
	proof := &dlog.Proof{
		C:         signature.C,
		S:         signature.S,
		Statement: publicKey.Y,
	}

	if err := dlog.Verify(cipherSuite.Curve.Point.Generator(), proof, message, nil); err != nil {
		return errors.Wrap(err, "couldn't verify underlying schnor proof")
	}
	return nil
}
