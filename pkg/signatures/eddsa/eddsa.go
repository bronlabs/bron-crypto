package eddsa

import (
	"bytes"
	"crypto/sha512"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

type Signature schnorr.Signature

type PublicKey schnorr.PublicKey

func (s *Signature) MarshalBinary() ([]byte, error) {
	serializedSignature := bytes.Join([][]byte{
		s.R.ToAffineCompressed(),
		bitstring.ReverseBytes(s.S.Bytes()),
	}, nil)
	return serializedSignature, nil
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	serializedPublicKey := pk.A.ToAffineCompressed()
	return serializedPublicKey, nil
}
func MakeEdDSACompatibleChallenge(xs ...[]byte) (curves.Scalar, error) {
	for _, x := range xs {
		if x == nil {
			return nil, errs.NewIsNil("an input is nil")
		}
	}
	digest, err := hashing.Hash(sha512.New, xs...)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not compute fiat shamir hash")
	}
	challenge, err := edwards25519.NewCurve().Scalar().SetBytesWide(bitstring.ReverseBytes(digest))
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not compute fiat shamir challenge")
	}
	return challenge, nil
}

func Verify(suite types.SignatureProtocol, publicKey *PublicKey, message []byte, signature *Signature) error {
	if !schnorr.IsEd25519Compliant(suite) {
		return errs.NewVerification("unsupported cipher suite")
	}

	if err := schnorr.Verify(suite, &schnorr.PublicKey{
		A: publicKey.A,
	}, message, &schnorr.Signature{
		R: signature.R,
		S: signature.S,
		E: signature.E,
	}); err != nil {
		return errs.WrapVerification(err, "invalid signature")
	}
	return nil
}
