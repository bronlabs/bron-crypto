package k256

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

var (
	_ cbor.Marshaler   = (*BaseFieldElement)(nil)
	_ cbor.Unmarshaler = (*BaseFieldElement)(nil)
	_ cbor.Marshaler   = (*Scalar)(nil)
	_ cbor.Unmarshaler = (*Scalar)(nil)
	_ cbor.Marshaler   = (*Point)(nil)
	_ cbor.Unmarshaler = (*Point)(nil)
)

type baseFieldDTO struct {
	BaseFieldBytes []byte `cbor:"fieldBytes"`
}

func (fe *BaseFieldElement) MarshalCBOR() ([]byte, error) {
	dto := &baseFieldDTO{BaseFieldBytes: fe.Bytes()}
	return serde.MarshalCBOR(dto)
}

func (fe *BaseFieldElement) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*baseFieldDTO](data)
	if err != nil {
		return err
	}

	bfe, err := NewBaseField().FromBytes(dto.BaseFieldBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize base field element")
	}
	fe.V.Set(&bfe.V)
	return nil
}

type scalarDTO struct {
	ScalarBytes []byte `cbor:"fieldBytes"`
}

func (fe *Scalar) MarshalCBOR() ([]byte, error) {
	dto := &scalarDTO{ScalarBytes: fe.Bytes()}
	return serde.MarshalCBOR(dto)
}

func (fe *Scalar) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*scalarDTO](data)
	if err != nil {
		return err
	}

	s, err := NewScalarField().FromBytes(dto.ScalarBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize scalar")
	}
	fe.V.Set(&s.V)
	return nil
}

type pointDTO struct {
	AffineCompressedBytes []byte `cbor:"compressedBytes"`
}

func (p *Point) MarshalCBOR() ([]byte, error) {
	dto := &pointDTO{AffineCompressedBytes: p.ToCompressed()}
	return serde.MarshalCBOR(dto)
}

func (p *Point) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[pointDTO](data)
	if err != nil {
		return err
	}

	pp, err := NewCurve().FromCompressed(dto.AffineCompressedBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}
