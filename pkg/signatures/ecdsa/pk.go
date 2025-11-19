package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

type PublicKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	pk P
}

type publicKeyDTO[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	PK P `cbor:"publicKey"`
}

func NewPublicKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](pk P) (*PublicKey[P, B, S], error) {
	if pk.IsZero() {
		return nil, errs.NewFailed("public key is zero")
	}
	if _, err := algebra.StructureAs[Curve[P, B, S]](pk.Structure()); err != nil {
		return nil, errs.WrapFailed(err, "curve structure is not supported")
	}

	key := &PublicKey[P, B, S]{
		pk: pk,
	}
	return key, nil
}

func (pk *PublicKey[P, B, S]) Value() P {
	return pk.pk
}

func (pk *PublicKey[P, B, S]) Clone() *PublicKey[P, B, S] {
	if pk == nil {
		return nil
	}

	clone := &PublicKey[P, B, S]{
		pk: pk.pk.Clone(),
	}
	return clone
}

func (pk *PublicKey[P, B, S]) Equal(rhs *PublicKey[P, B, S]) bool {
	if pk == nil || rhs == nil {
		return pk == rhs
	}

	return pk.pk.Equal(rhs.pk)
}

func (pk *PublicKey[P, B, S]) HashCode() base.HashCode {
	return pk.pk.HashCode()
}

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

func (pk *PublicKey[P, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO[P, B, S]{
		PK: pk.pk,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal ECDSA PublicKey")
	}
	return data, nil
}

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
