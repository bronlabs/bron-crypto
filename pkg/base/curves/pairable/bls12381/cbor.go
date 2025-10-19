package bls12381

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

var (
	_ cbor.Marshaler   = (*BaseFieldElementG1)(nil)
	_ cbor.Unmarshaler = (*BaseFieldElementG1)(nil)
	_ cbor.Marshaler   = (*BaseFieldElementG2)(nil)
	_ cbor.Unmarshaler = (*BaseFieldElementG2)(nil)
	_ cbor.Marshaler   = (*Scalar)(nil)
	_ cbor.Unmarshaler = (*Scalar)(nil)
	_ cbor.Marshaler   = (*PointG1)(nil)
	_ cbor.Unmarshaler = (*PointG1)(nil)
	_ cbor.Marshaler   = (*PointG2)(nil)
	_ cbor.Unmarshaler = (*PointG2)(nil)
)

type baseFieldElementG1DTO struct {
	FieldBytes []byte `cbor:"fieldBytes"`
}

func (fe *BaseFieldElementG1) MarshalCBOR() ([]byte, error) {
	dto := &baseFieldElementG1DTO{FieldBytes: fe.Bytes()}
	return serde.MarshalCBOR(dto)
}

func (fe *BaseFieldElementG1) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*baseFieldElementG1DTO](data)
	if err != nil {
		return err
	}
	e, err := NewG1BaseField().FromBytes(dto.FieldBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize base field element")
	}
	fe.V.Set(&e.V)
	return nil
}

type baseFieldElementG2DTO struct {
	FieldBytes []byte `cbor:"fieldBytes"`
}

func (fe *BaseFieldElementG2) MarshalCBOR() ([]byte, error) {
	dto := &baseFieldElementG2DTO{FieldBytes: fe.Bytes()}
	return serde.MarshalCBOR(dto)
}

func (fe *BaseFieldElementG2) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*baseFieldElementG2DTO](data)
	if err != nil {
		return err
	}
	e, err := NewG2BaseField().FromBytes(dto.FieldBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize base field element")
	}
	fe.V.Set(&e.V)
	return nil
}

type scalarDTO struct {
	FieldBytes []byte `cbor:"fieldBytes"`
}

func (s *Scalar) MarshalCBOR() ([]byte, error) {
	dto := &scalarDTO{FieldBytes: s.Bytes()}
	return serde.MarshalCBOR(dto)
}

func (s *Scalar) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*scalarDTO](data)
	if err != nil {
		return err
	}
	e, err := NewScalarField().FromBytes(dto.FieldBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize scalar")
	}
	s.V.Set(&e.V)
	return nil
}

type pointG1DTO struct {
	AffineCompressedBytes []byte `cbor:"compressedBytes"`
}

func (p *PointG1) MarshalCBOR() ([]byte, error) {
	dto := &pointG1DTO{AffineCompressedBytes: p.ToCompressed()}
	return serde.MarshalCBOR(dto)
}

func (p *PointG1) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*pointG1DTO](data)
	if err != nil {
		return err
	}
	e, err := NewG1().FromCompressed(dto.AffineCompressedBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize scalar")
	}
	p.V.Set(&e.V)
	return nil
}

type pointG2DTO struct {
	AffineCompressedBytes []byte `cbor:"compressedBytes"`
}

func (p *PointG2) MarshalCBOR() ([]byte, error) {
	dto := &pointG2DTO{AffineCompressedBytes: p.ToCompressed()}
	return serde.MarshalCBOR(dto)
}

func (p *PointG2) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*pointG2DTO](data)
	if err != nil {
		return err
	}
	e, err := NewG2().FromCompressed(dto.AffineCompressedBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize scalar")
	}
	p.V.Set(&e.V)
	return nil
}
