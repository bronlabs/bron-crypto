package curve25519

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/fxamacker/cbor/v2"
)

var (
	_ cbor.Unmarshaler = (*Scalar)(nil)
	_ cbor.Marshaler   = (*Point)(nil)
	_ cbor.Unmarshaler = (*Point)(nil)
	_ cbor.Marshaler   = (*PrimeSubGroupPoint)(nil)
	_ cbor.Unmarshaler = (*PrimeSubGroupPoint)(nil)
)

type pointDTO struct {
	AffineCompressedBytes []byte `cbor:"compressedBytes"`
}

func (p *Point) MarshalCBOR() ([]byte, error) {
	dto := &pointDTO{AffineCompressedBytes: p.ToCompressed()}
	return serde.MarshalCBOR(dto)
}

func (p *Point) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*pointDTO](data)
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

func (p *PrimeSubGroupPoint) MarshalCBOR() ([]byte, error) {
	dto := &pointDTO{AffineCompressedBytes: p.ToCompressed()}
	return serde.MarshalCBOR(dto)
}

func (p *PrimeSubGroupPoint) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*pointDTO](data)
	if err != nil {
		return err
	}

	pp, err := NewPrimeSubGroup().FromCompressed(dto.AffineCompressedBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}
