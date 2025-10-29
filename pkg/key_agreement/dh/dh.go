package dh

// import (
// 	"crypto/ecdh"
// 	"slices"

// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/base/ct"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
// 	"github.com/bronlabs/bron-crypto/pkg/key_agreement"
// 	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
// )

// type (
// 	PrivateKey[S algebra.PrimeFieldElement[S]] struct {
// 		vBE []byte // big endian
// 		s   S
// 		t   key_agreement.Type
// 	}
// 	PublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = key_agreement.PublicKey[P, S]
// 	SharedKey[B algebra.FiniteFieldElement[B]]                                                          = key_agreement.SharedKey
// )

// const (
// 	X25519 key_agreement.Type = "X25519"
// 	X448   key_agreement.Type = "X448"
// )

// func DeriveSharedSecret[
// 	P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S],
// ](privateKey *PrivateKey[S], publicKey *PublicKey[P, B, S]) (sharedSecretValue *SharedKey[B], err error) {
// 	if publicKey == nil {
// 		return nil, errs.NewIsNil("publicKey")
// 	}
// 	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](publicKey.Value().Structure())
// 	switch curve.Name() {
// 	case curve25519.NewPrimeSubGroup().Name():
// 		return doX25519(privateKey.vBE, publicKey)
// 	default:
// 		return doIEEE(privateKey, publicKey)
// 	}
// }

// func doX25519[ // Because Go doesn't allow casting a generic struct to another generic struct with fixed type parameters, this function has to be generic even though it only works for Curve25519.
// 	P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S],
// ](ikm []byte, publicKey *PublicKey[P, B, S]) (*SharedKey[B], error) {
// 	if publicKey.Type() != X25519 {
// 		return nil, errs.NewValidation("public key is not of type X25519")
// 	}
// 	if len(ikm) != 32 {
// 		return nil, errs.NewValidation("invalid ikm length for x25519 private key")
// 	}
// 	x25519 := ecdh.X25519()
// 	sk, err := x25519.NewPrivateKey(ikm)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not create x25519 private key from ikm")
// 	}
// 	pk, err := x25519.NewPublicKey(publicKey.Value().ToCompressed())
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not create x25519 public key from bytes")
// 	}
// 	xBytes, err := sk.ECDH(pk)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not derive shared secret using x25519")
// 	}
// 	slices.Reverse(xBytes) // was little-endian (https://rfc-editor.org/rfc/rfc7748.html#section-5), convert to big-endian as it's our api convention
// 	out, err := curve25519.NewBaseField().FromBytes(xBytes)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not create base field element from shared secret bytes")
// 	}
// 	return NewSharedKey(out)
// }

// func doIEEE[
// 	P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S],
// ](privateKey *PrivateKey[S], publicKey *PublicKey[P, B, S]) (*SharedKey[B], error) {
// 	if publicKey.Type() == X25519 {
// 		return nil, errs.NewValidation("public key is of type X25519, cannot use IEEE method")
// 	}
// 	sk, err := dhc.NewPrivateKey(privateKey.s)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not create private key")
// 	}
// 	sharedSecret, err := dhc.DeriveSharedSecret(sk, publicKey)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not derive shared secret using dhc")
// 	}
// 	return sharedSecret, nil
// }

// func typ(name string) key_agreement.Type {
// 	switch name {
// 	case curve25519.CurveName, curve25519.PrimeCurveName, curve25519.ScalarFieldName, curve25519.BaseFieldName:
// 		return X25519
// 	default:
// 		return dhc.Type
// 	}
// }

// func NewPrivateKey[S algebra.PrimeFieldElement[S]](sf algebra.PrimeField[S], v []byte) (*PrivateKey[S], error) {
// 	if sf == nil {
// 		return nil, errs.NewIsNil("scalar field")
// 	}
// 	if len(v) == 0 {
// 		return nil, errs.NewIsZero("private key bytes")
// 	}
// 	t := typ(sf.Name())
// 	f := sf.FromBytes
// 	if t == X25519 {
// 		f = algebra.StructureMustBeAs[interface {
// 			algebra.PrimeField[S]
// 			FromClampedBytes([]byte) (S, error)
// 		}](sf).FromClampedBytes
// 	}
// 	s, err := f(v)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not create private key scalar from bytes")
// 	}
// 	return &PrivateKey[S]{vBE: v, s: s, t: t}, nil
// }

// func (sk *PrivateKey[S]) Type() key_agreement.Type {
// 	return sk.t
// }

// func (sk *PrivateKey[S]) Value() S {
// 	return sk.s
// }

// func (sk *PrivateKey[S]) Bytes() []byte {
// 	return sk.vBE
// }

// func (sk *PrivateKey[S]) Equal(other *PrivateKey[S]) bool {
// 	if sk == nil && other == nil {
// 		return sk == other
// 	}
// 	return ct.SliceEqual(sk.vBE, other.vBE) == ct.True && sk.s.Equal(other.s) && sk.t == other.t
// }

// func NewPublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](v P) (*PublicKey[P, B, S], error) {
// 	return key_agreement.NewPublicKey(v, typ(v.Structure().Name()))
// }

// func NewSharedKey[B algebra.FiniteFieldElement[B]](v B) (*SharedKey[B], error) {
// 	t := typ(v.Structure().Name())
// 	var b []byte
// 	if t == X25519 {
// 		b = sliceutils.Reversed(v.Bytes()) // go x25519 expects little-endian
// 	} else {
// 		b = v.Bytes()
// 	}
// 	return key_agreement.NewSharedKey(b, typ(v.Structure().Name()))
// }
