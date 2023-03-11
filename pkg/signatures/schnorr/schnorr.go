package schnorr

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"github.com/pkg/errors"
)

type PrivateKey struct {
	Curve *curves.Curve
	a     curves.Scalar
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

func Keygen(curve *curves.Curve, secret curves.Scalar, reader io.Reader) *PrivateKey {
	if secret == nil {
		secret = curve.Scalar.Random(reader)
	}
	publicKey := curve.ScalarBaseMult(secret)
	return &PrivateKey{
		Curve: curve,
		a:     secret,
		PublicKey: PublicKey{
			Curve: curve,
			Y:     publicKey,
		},
	}
}

func (k *PrivateKey) Sign(reader io.Reader, message []byte, parameters [][]byte) (*Signature, error) {
	prover := schnorr.NewProver(k.Curve, nil, message, parameters)
	proof, err := prover.Prove(k.a)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't make proof of knowledge of discrete log of public key bound with the message")
	}
	return &Signature{
		C: proof.C,
		S: proof.S,
	}, nil
}

func Verify(publicKey *PublicKey, message []byte, signature *Signature, parameters [][]byte) error {
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
	proof := &schnorr.Proof{
		C:         signature.C,
		S:         signature.S,
		Statement: publicKey.Y,
	}
	if err := schnorr.Verify(proof, publicKey.Curve, nil, message, parameters); err != nil {
		return errors.Wrap(err, "couldn't verify underlying schnor proof")
	}
	return nil
}
