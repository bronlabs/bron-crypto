package pasta

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
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

// MarshalCBOR implements cbor.Marshaler.
func (fe *FpFieldElement) MarshalCBOR() ([]byte, error) {
	dto := &fpFieldElementDTO{FieldBytes: fe.Bytes()}
	return serde.MarshalCBOR(dto)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (fe *FpFieldElement) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*fpFieldElementDTO](data)
	if err != nil {
		return err
	}

	bfe, err := newFpField().FromBytes(dto.FieldBytes)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot deserialize base field element")
	}
	fe.V.Set(&bfe.V)
	return nil
}

type fqFieldElementDTO struct {
	FieldBytes []byte `cbor:"fieldBytes"`
}

// MarshalCBOR implements cbor.Marshaler.
func (fe *FqFieldElement) MarshalCBOR() ([]byte, error) {
	dto := &fqFieldElementDTO{FieldBytes: fe.Bytes()}
	return serde.MarshalCBOR(dto)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (fe *FqFieldElement) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*fqFieldElementDTO](data)
	if err != nil {
		return err
	}

	s, err := newFqField().FromBytes(dto.FieldBytes)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot deserialize scalar")
	}
	fe.V.Set(&s.V)
	return nil
}

type pallasPointDTO struct {
	AffineCompressedBytes []byte `cbor:"compressedBytes"`
}

// MarshalCBOR implements cbor.Marshaler.
func (p *PallasPoint) MarshalCBOR() ([]byte, error) {
	dto := &pallasPointDTO{AffineCompressedBytes: p.ToCompressed()}
	return serde.MarshalCBOR(dto)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (p *PallasPoint) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*pallasPointDTO](data)
	if err != nil {
		return err
	}

	pp, err := NewPallasCurve().FromCompressed(dto.AffineCompressedBytes)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

type vestaPointDTO struct {
	AffineCompressedBytes []byte `cbor:"compressedBytes"`
}

// MarshalCBOR implements cbor.Marshaler.
func (p *VestaPoint) MarshalCBOR() ([]byte, error) {
	dto := &vestaPointDTO{AffineCompressedBytes: p.ToCompressed()}
	return serde.MarshalCBOR(dto)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (p *VestaPoint) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*vestaPointDTO](data)
	if err != nil {
		return err
	}

	pp, err := NewVestaCurve().FromCompressed(dto.AffineCompressedBytes)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}
