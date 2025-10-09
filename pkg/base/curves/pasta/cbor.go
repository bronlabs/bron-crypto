package pasta

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/fxamacker/cbor/v2"
)

var (
	_ cbor.Marshaler   = (*PallasBaseFieldElement)(nil)
	_ cbor.Unmarshaler = (*PallasBaseFieldElement)(nil)
	_ cbor.Marshaler   = (*PallasScalar)(nil)
	_ cbor.Unmarshaler = (*PallasScalar)(nil)
	_ cbor.Marshaler   = (*PallasPoint)(nil)
	_ cbor.Unmarshaler = (*PallasPoint)(nil)

	_ cbor.Marshaler   = (*VestaBaseFieldElement)(nil)
	_ cbor.Unmarshaler = (*VestaBaseFieldElement)(nil)
	_ cbor.Marshaler   = (*VestaScalar)(nil)
	_ cbor.Unmarshaler = (*VestaScalar)(nil)
	_ cbor.Marshaler   = (*VestaPoint)(nil)
	_ cbor.Unmarshaler = (*VestaPoint)(nil)
)

type fpFieldElementDTO struct {
	FieldBytes []byte `cbor:"fieldBytes"`
}

func (fe *FpFieldElement) MarshalCBOR() ([]byte, error) {
	dto := &fpFieldElementDTO{FieldBytes: fe.Bytes()}
	return serde.MarshalCBOR(dto)
}

func (fe *FpFieldElement) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*fpFieldElementDTO](data)
	if err != nil {
		return err
	}

	bfe, err := newFpField().FromBytes(dto.FieldBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize base field element")
	}
	fe.V.Set(&bfe.V)
	return nil
}

type fqFieldElementDTO struct {
	FieldBytes []byte `cbor:"fieldBytes"`
}

func (fe *FqFieldElement) MarshalCBOR() ([]byte, error) {
	dto := &fqFieldElementDTO{FieldBytes: fe.Bytes()}
	return serde.MarshalCBOR(dto)
}

func (fe *FqFieldElement) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*fqFieldElementDTO](data)
	if err != nil {
		return err
	}

	s, err := newFqField().FromBytes(dto.FieldBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize scalar")
	}
	fe.V.Set(&s.V)
	return nil
}

type pallasPointDTO struct {
	AffineCompressedBytes []byte `cbor:"compressedBytes"`
}

func (p *PallasPoint) MarshalCBOR() ([]byte, error) {
	dto := &pallasPointDTO{AffineCompressedBytes: p.ToCompressed()}
	return serde.MarshalCBOR(dto)
}

func (p *PallasPoint) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*pallasPointDTO](data)
	if err != nil {
		return err
	}

	pp, err := NewPallasCurve().FromCompressed(dto.AffineCompressedBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

type vestaPointDTO struct {
	AffineCompressedBytes []byte `cbor:"compressedBytes"`
}

func (p *VestaPoint) MarshalCBOR() ([]byte, error) {
	dto := &vestaPointDTO{AffineCompressedBytes: p.ToCompressed()}
	return serde.MarshalCBOR(dto)
}

func (p *VestaPoint) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*vestaPointDTO](data)
	if err != nil {
		return err
	}

	pp, err := NewVestaCurve().FromCompressed(dto.AffineCompressedBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}
