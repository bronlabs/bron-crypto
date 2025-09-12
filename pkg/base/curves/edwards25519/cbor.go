package edwards25519

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/fxamacker/cbor/v2"
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
	BaseFieldBytes []byte `cbor:"1"`
}

func (fe *BaseFieldElement) MarshalCBOR() ([]byte, error) {
	dto := &baseFieldDTO{BaseFieldBytes: fe.Bytes()}
	return cbor.Marshal(dto)
}

func (fe *BaseFieldElement) UnmarshalCBOR(data []byte) error {
	var dto baseFieldDTO
	if err := cbor.Unmarshal(data, &dto); err != nil {
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
	ScalarBytes []byte `cbor:"1"`
}

func (fe *Scalar) MarshalCBOR() ([]byte, error) {
	dto := &scalarDTO{ScalarBytes: fe.Bytes()}
	return cbor.Marshal(dto)
}

func (fe *Scalar) UnmarshalCBOR(data []byte) error {
	var dto scalarDTO
	if err := cbor.Unmarshal(data, &dto); err != nil {
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
	AffineCompressedBytes []byte `cbor:"1"`
}

func (p *Point) MarshalCBOR() ([]byte, error) {
	dto := &pointDTO{AffineCompressedBytes: p.ToCompressed()}
	return cbor.Marshal(dto)
}

func (p *Point) UnmarshalCBOR(data []byte) error {
	var dto pointDTO
	if err := cbor.Unmarshal(data, &dto); err != nil {
		return err
	}

	pp, err := NewCurve().FromCompressed(dto.AffineCompressedBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}
