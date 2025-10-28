package dh

import (
	"crypto/ecdh"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/internal"
)

type (
	PrivateKey[S algebra.PrimeFieldElement[S]]                                                          = key_agreement.PrivateKey[S]
	PublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = key_agreement.PublicKey[P, S]
	SharedKey[B algebra.FiniteFieldElement[B]]                                                          = key_agreement.SharedKey
)

const (
	X25519 key_agreement.Type = "X25519"
	X448   key_agreement.Type = "X448"
)

func DeriveSharedSecret[
	P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S],
](rawPrivateKey []byte, publicKey PublicKey[P, B, S]) (sharedSecretValue SharedKey[B], err error) {
	if publicKey == nil {
		return nil, errs.NewIsNil("publicKey")
	}
	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](publicKey.Value().Structure())
	switch curve.Name() {
	case curve25519.NewPrimeSubGroup().Name():
		pk, ok := publicKey.(key_agreement.PublicKey[*curve25519.PrimeSubGroupPoint, *curve25519.Scalar])
		if !ok {
			return nil, errs.NewValidation("public key is not of type X25519")
		}
		return doX25519(rawPrivateKey, pk)
	default:
		return doIEEE(curve, rawPrivateKey, publicKey)
	}
}

func doX25519(ikm []byte, publicKey key_agreement.PublicKey[*curve25519.PrimeSubGroupPoint, *curve25519.Scalar]) (SharedKey[*curve25519.BaseFieldElement], error) {
	if publicKey.Type() != X25519 {
		return nil, errs.NewValidation("public key is not of type X25519")
	}
	if len(ikm) != 32 {
		return nil, errs.NewValidation("invalid ikm length for x25519 private key")
	}
	x25519 := ecdh.X25519()
	sk, err := x25519.NewPrivateKey(ikm)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create x25519 private key from ikm")
	}
	pk, err := x25519.NewPublicKey(publicKey.Value().ToCompressed())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create x25519 public key from bytes")
	}
	xBytes, err := sk.ECDH(pk)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive shared secret using x25519")
	}
	slices.Reverse(xBytes) // was little-endian (https://rfc-editor.org/rfc/rfc7748.html#section-5), convert to big-endian as it's our api convention
	out, err := curve25519.NewBaseField().FromBytes(xBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create base field element from shared secret bytes")
	}
	return NewSharedKey(out)
}

func doIEEE[
	P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S],
](curve curves.Curve[P, B, S], rawPrivateKey []byte, publicKey PublicKey[P, B, S]) (SharedKey[B], error) {
	if publicKey.Type() == X25519 {
		return nil, errs.NewValidation("public key is of type X25519, cannot use IEEE method")
	}
	skv, err := curve.ScalarField().FromBytes(rawPrivateKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create private key scalar from bytes")
	}
	sk, err := dhc.NewPrivateKey(skv)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create private key")
	}
	sharedSecret, err := dhc.DeriveSharedSecret(sk, publicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive shared secret using dhc")
	}
	return sharedSecret, nil
}

func typ(name string) key_agreement.Type {
	switch name {
	case curve25519.CurveName, curve25519.PrimeCurveName, curve25519.ScalarFieldName, curve25519.BaseFieldName:
		return X25519
	default:
		return dhc.Type
	}
}

func NewPrivateKey[S algebra.PrimeFieldElement[S]](v S) (PrivateKey[S], error) {
	if v.IsZero() {
		return nil, errs.NewIsZero("invalid private key")
	}
	return key_agreement.NewPrivateKey(v, typ(v.Structure().Name())), nil
}

func NewPublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](v P) (PublicKey[P, B, S], error) {
	if v.IsOpIdentity() || !v.IsTorsionFree() {
		return nil, errs.NewIsIdentity("invalid public key")
	}
	return key_agreement.NewPublicKey(v, typ(v.Structure().Name())), nil
}

func NewSharedKey[B algebra.FiniteFieldElement[B]](v B) (SharedKey[B], error) {
	if ct.SliceIsZero(v.Bytes()) == ct.True {
		return nil, errs.NewIsZero("invalid shared key")
	}
	internalSharedKey := internal.NewSharedKey(v.Bytes(), typ(v.Structure().Name()))
	return &sharedKey[B]{
		SharedKey: *internalSharedKey,
		v:         v,
	}, nil
}

type sharedKey[B algebra.FiniteFieldElement[B]] struct {
	internal.SharedKey[key_agreement.Type]
	v algebra.FiniteFieldElement[B]
}

func (k *sharedKey[B]) Value() algebra.FiniteFieldElement[B] {
	return k.v
}

func (k *sharedKey[B]) Bytes() []byte {
	out := k.SharedKey.Bytes()
	if k.Type() == X25519 {
		slices.Reverse(out) // convert back to little-endian for X25519
	}
	return out
}
