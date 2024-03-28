package eddsa

import (
	"crypto/sha512"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	vanillaSchnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

type Signature = schnorr.Signature[schnorr.EdDsaCompatibleVariant]

type PublicKey vanillaSchnorr.PublicKey

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

func Verify(suite types.SigningSuite, publicKey *PublicKey, message []byte, signature *Signature) error {
	if !vanillaSchnorr.IsEd25519Compliant(suite) {
		return errs.NewVerification("unsupported cipher suite")
	}

	if err := vanillaSchnorr.Verify(suite, &vanillaSchnorr.PublicKey{A: publicKey.A}, message, signature); err != nil {
		return errs.WrapVerification(err, "invalid signature")
	}
	return nil
}
