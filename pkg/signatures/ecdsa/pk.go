package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// PublicKey represents an ECDSA public key as a point on an elliptic curve.
// The public key Q is computed as Q = d * G, where d is the private key scalar
// and G is the curve's generator point.
type PublicKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	pk P
}

type publicKeyDTO[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	PK P `cbor:"publicKey"`
}

// NewPublicKey creates a PublicKey from an elliptic curve point.
// The point must be a valid, non-zero point on a supported ECDSA curve.
func NewPublicKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](pk P) (*PublicKey[P, B, S], error) {
	if pk.IsZero() {
		return nil, ErrFailed.WithMessage("public key is zero")
	}
	if _, err := algebra.StructureAs[Curve[P, B, S]](pk.Structure()); err != nil {
		return nil, errs2.Wrap(err).WithMessage("curve structure is not supported")
	}

	key := &PublicKey[P, B, S]{
		pk: pk,
	}
	return key, nil
}

// Value returns the underlying elliptic curve point.
func (pk *PublicKey[P, B, S]) Value() P {
	return pk.pk
}

// Clone returns a deep copy of the public key.
func (pk *PublicKey[P, B, S]) Clone() *PublicKey[P, B, S] {
	if pk == nil {
		return nil
	}

	clone := &PublicKey[P, B, S]{
		pk: pk.pk.Clone(),
	}
	return clone
}

// Equal returns true if both public keys represent the same curve point.
func (pk *PublicKey[P, B, S]) Equal(rhs *PublicKey[P, B, S]) bool {
	if pk == nil || rhs == nil {
		return pk == rhs
	}

	return pk.pk.Equal(rhs.pk)
}

// HashCode returns a hash of the public key for use in hash-based data structures.
func (pk *PublicKey[P, B, S]) HashCode() base.HashCode {
	return pk.pk.HashCode()
}

// ToElliptic converts the public key to Go's standard library ecdsa.PublicKey format.
// This enables interoperability with Go's crypto/ecdsa package.
func (pk *PublicKey[P, B, S]) ToElliptic() *nativeEcdsa.PublicKey {
	curve := algebra.StructureMustBeAs[Curve[P, B, S]](pk.pk.Structure())
	nativeCurve := curve.ToElliptic()
	nativeX := errs2.Must1(pk.Value().AffineX()).Cardinal().Big()
	nativeY := errs2.Must1(pk.Value().AffineY()).Cardinal().Big()
	nativePublicKey := &nativeEcdsa.PublicKey{
		Curve: nativeCurve,
		X:     nativeX,
		Y:     nativeY,
	}
	return nativePublicKey
}

// MarshalCBOR serializes the public key to CBOR format.
func (pk *PublicKey[P, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO[P, B, S]{
		PK: pk.pk,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to marshal ECDSA PublicKey")
	}
	return data, nil
}

// UnmarshalCBOR deserializes a public key from CBOR format.
func (pk *PublicKey[P, B, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*publicKeyDTO[P, B, S]](data)
	if err != nil {
		return err
	}

	pk2, err := NewPublicKey(dto.PK)
	if err != nil {
		return err
	}
	*pk = *pk2
	return nil
}
