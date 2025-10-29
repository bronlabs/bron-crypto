package dhc

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement"
)

const Type key_agreement.Type = "ECSVDP-DHC"

type (
	PrivateKey struct {
		v []byte
	}
	ExtendedPrivateKey[S algebra.PrimeFieldElement[S]] struct {
		PrivateKey
		s S
	}
	PublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = key_agreement.PublicKey[P, S]
	SharedKey[B algebra.FiniteFieldElement[B]]                                                          = key_agreement.SharedKey
)

func DeriveSharedSecret[
	P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S],
](myPrivateKey *ExtendedPrivateKey[S], otherPartyPublicKey *PublicKey[P, B, S]) (*SharedKey[B], error) {
	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](otherPartyPublicKey.Value().Structure())
	if myPrivateKey == nil || otherPartyPublicKey == nil {
		return nil, errs.NewIsNil("nil key provided")
	}
	if myPrivateKey.Type() != Type || otherPartyPublicKey.Type() != Type {
		return nil, errs.NewValidation("incompatible key types")
	}
	// assumption 1
	if myPrivateKey.Value().IsZero() {
		return nil, errs.NewIsZero("invalid private key")
	}
	if !otherPartyPublicKey.Value().IsTorsionFree() {
		return nil, errs.NewValidation("Public Key not in the prime subgroup")
	}
	// step 1
	k, err := curve.ScalarField().FromCardinal(curve.Cofactor())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get cofactor")
	}
	kInv, err := k.TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get inverse")
	}
	t := kInv.Mul(myPrivateKey.Value())
	// step 2
	bigP := otherPartyPublicKey.Value().ScalarMul(k.Mul(t))
	// step 3
	if bigP.IsZero() {
		return nil, errs.NewIsIdentity("invalid public key")
	}
	// step 4
	x, err := bigP.AffineX()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get affine x coordinate")
	}
	// step 5
	return NewSharedKey(x)
}

func SerialiseExtendedPrivateKey[S algebra.PrimeFieldElement[S]](sk *ExtendedPrivateKey[S]) ([]byte, error) {
	if sk == nil {
		return nil, errs.NewIsNil("extended private key")
	}
	return sk.v, nil
}

func SerialisePublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pk *PublicKey[P, B, S]) ([]byte, error) {
	if pk == nil {
		return nil, errs.NewIsNil("public key")
	}
	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](pk.Value().Structure())
	var out []byte
	if isFromCurve25519(curve.Name()) || isFromEdwards25519(curve.Name()) {
		out = pk.Value().ToCompressed()
	} else {
		out = pk.Value().ToUncompressed()
	}
	return out, nil
}

func SerialiseSharedKey[B algebra.FiniteFieldElement[B]](k *SharedKey[B]) ([]byte, error) {
	if k == nil {
		return nil, errs.NewIsNil("shared key")
	}
	return k.Bytes(), nil
}

func NewPrivateKey(v []byte) (*PrivateKey, error) {
	if ct.SliceIsZero(v) == ct.True {
		return nil, errs.NewIsZero("private key bytes")
	}
	return &PrivateKey{v: slices.Clone(v)}, nil
}

func (sk *PrivateKey) Value() []byte {
	return sk.v
}

func (sk *PrivateKey) Type() key_agreement.Type {
	return Type
}

func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	if sk == nil && other == nil {
		return sk == other
	}
	return ct.SliceEqual(sk.v, other.v) == ct.True
}

func ExtendPrivateKey[S algebra.PrimeFieldElement[S]](sk *PrivateKey, sf algebra.PrimeField[S]) (*ExtendedPrivateKey[S], error) {
	if sk == nil {
		return nil, errs.NewIsNil("private key")
	}
	if sf == nil {
		return nil, errs.NewIsNil("sf")
	}
	var s S
	var err error
	if isFromCurve25519(sf.Name()) {
		sf := algebra.StructureMustBeAs[interface {
			algebra.PrimeField[S]
			FromClampedBytes([]byte) (S, error)
		}](sf)
		s, err = sf.FromClampedBytes(sliceutils.Reversed(sk.Value())) // X25519 would have expected little-endian
	} else {
		s, err = sf.FromBytes(sk.Value())
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive extended private key")
	}
	if s.IsZero() {
		return nil, errs.NewIsZero("invalid private key scalar")
	}
	return &ExtendedPrivateKey[S]{PrivateKey: *sk, s: s}, nil
}

func NewExtendedPrivateKey[S algebra.PrimeFieldElement[S]](s S) (*ExtendedPrivateKey[S], error) {
	return &ExtendedPrivateKey[S]{PrivateKey: PrivateKey{v: s.Bytes()}, s: s}, nil
}

func (sk *ExtendedPrivateKey[S]) Value() S {
	return sk.s
}

func (sk *ExtendedPrivateKey[S]) Bytes() []byte {
	return sk.v // this may be little-endian if from X25519
}

func (sk *ExtendedPrivateKey[S]) Equal(other *ExtendedPrivateKey[S]) bool {
	if sk == nil && other == nil {
		return sk == other
	}
	return ct.SliceEqual(sk.v, other.v) == ct.True && sk.s.Equal(other.s)
}

func NewPublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](v P) (*PublicKey[P, B, S], error) {
	return key_agreement.NewPublicKey(v, Type)
}

func NewSharedKey[B algebra.FiniteFieldElement[B]](v B) (*SharedKey[B], error) {
	var b []byte
	if isFromCurve25519(v.Structure().Name()) {
		b = sliceutils.Reversed(v.Bytes()) // X25519 expects little-endian
	} else {
		b = v.Bytes()
	}
	return key_agreement.NewSharedKey(b, Type)
}

func isFromCurve25519(name string) bool {
	switch name {
	case curve25519.PrimeCurveName, curve25519.ScalarFieldName, curve25519.BaseFieldName:
		return true
	default:
		return false
	}
}

func isFromEdwards25519(name string) bool {
	switch name {
	case edwards25519.PrimeCurveName, edwards25519.ScalarFieldName, edwards25519.BaseFieldName:
		return true
	default:
		return false
	}
}
