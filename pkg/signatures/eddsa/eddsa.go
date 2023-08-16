package eddsa

import (
	"crypto/ed25519"
	"crypto/sha512"
	"hash"
	"reflect"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

type Signature struct {
	R curves.Point
	Z curves.Scalar

	_ helper_types.Incomparable
}

func (s *Signature) MarshalBinary() ([]byte, error) {
	signatureSize := 64
	if s.R.CurveName() == k256.Name || s.R.CurveName() == p256.Name {
		// these two curves add a bit at the beginning to denote compressed or uncompressed
		signatureSize = 65
	}
	serializedSignature := []byte{}
	RSerialized := s.R.ToAffineCompressed()
	zSerialized := s.Z.Bytes()
	if len(RSerialized)+len(zSerialized) != signatureSize {
		return serializedSignature, errs.NewDeserializationFailed("serialised signature is too large")
	}
	serializedSignature = append(serializedSignature, RSerialized...)
	serializedSignature = append(serializedSignature, zSerialized...)
	return serializedSignature, nil
}

func Verify(curve curves.Curve, hashFunction func() hash.Hash, signature *Signature, publicKey curves.Point, message []byte) error {
	if publicKey.IsIdentity() {
		return errs.NewVerificationFailed("public key is at infinity")
	}
	if curve.Name() == edwards25519.New().Name() {
		edwardsPoint, ok := publicKey.(*edwards25519.Point)
		if !ok {
			return errs.NewDeserializationFailed("curve is ed25519 but the public key could not be type casted to the correct point struct")
		}
		// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptibe
		// to a key substitution attack (specifically, it won't be binded to a public key (SBS) and a signature cannot be binded to a unique message in presence of malicious keys (MBS)). Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
		if edwardsPoint.IsSmallOrder() {
			return errs.NewFailed("public key is small order")
		}
		// is an eddsa compliant signature
		if reflect.ValueOf(hashFunction).Pointer() == reflect.ValueOf(sha512.New).Pointer() {
			serializedSignature, err := signature.MarshalBinary()
			if err != nil {
				return errs.WrapDeserializationFailed(err, "could not serialise signature to binary")
			}
			if ok := ed25519.Verify(publicKey.ToAffineCompressed(), message, serializedSignature); !ok {
				return errs.NewVerificationFailed("could not verify schnorr signature using ed25519 verifier")
			}
		}
		return nil
	} else {
		c, err := hashing.FiatShamir(&integration.CipherSuite{
			Curve: curve,
			Hash:  hashFunction,
		}, signature.R.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
		if err != nil {
			return errs.WrapDeserializationFailed(err, "fiat shamir failed")
		}

		zG := curve.ScalarBaseMult(signature.Z)
		negCY := publicKey.Mul(c.Neg())
		RPrime := zG.Add(negCY)
		if ok := signature.R.Equal(RPrime); !ok {
			return errs.NewVerificationFailed("failed to verify")
		}
		return nil
	}
}
