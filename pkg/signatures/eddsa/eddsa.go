package eddsa

import (
	"crypto/ed25519"
	"crypto/sha512"
	"reflect"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
	vanillaSchnorr "github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

type Signature = schnorr.Signature[vanillaSchnorr.EdDsaCompatibleVariant, []byte]

type PublicKey schnorr.PublicKey

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	serializedPublicKey := pk.A.ToAffineCompressed()
	return serializedPublicKey, nil
}

func Verify(publicKey *PublicKey, message []byte, signature *Signature) error {
	// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptible
	// to a key substitution attack (specifically, it won't be bound to a public key (SBS) and a signature cannot be bound to a unique message in presence of malicious keys (MBS)).
	// Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
	if publicKey.A.IsSmallOrder() {
		return errs.NewVerification("public key is small order")
	}
	if !publicKey.A.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	serialisedSignature, err := signature.MarshalBinary()
	if err != nil {
		return errs.WrapSerialisation(err, "could not serialise signature to binary")
	}
	serializedPublicKey, err := publicKey.MarshalBinary()
	if err != nil {
		return errs.WrapSerialisation(err, "could not serialise public key to binary")
	}
	if ok := ed25519.Verify(serializedPublicKey, message, serialisedSignature); !ok {
		return errs.NewVerification("could not verify schnorr signature using ed25519 verifier")
	}

	return nil
}

func IsEd25519Compliant(suite types.SigningSuite) bool {
	return (suite.Curve().Name() == edwards25519.Name) && (reflect.ValueOf(suite.Hash()).Pointer() == reflect.ValueOf(sha512.New).Pointer())
}
