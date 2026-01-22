package curve25519

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/errs-go/errs"
)

var (
	_ cbor.Unmarshaler = (*Scalar)(nil)
	_ cbor.Marshaler   = (*Point)(nil)
	_ cbor.Unmarshaler = (*Point)(nil)
	_ cbor.Marshaler   = (*PrimeSubGroupPoint)(nil)
	_ cbor.Unmarshaler = (*PrimeSubGroupPoint)(nil)
)

type pointDTO struct {
	AffineUnompressedBytes []byte `cbor:"compressedBytes"`
}

// MarshalCBOR implements cbor.Marshaler.
func (p *Point) MarshalCBOR() ([]byte, error) {
	dto := &pointDTO{AffineUnompressedBytes: p.ToUncompressed()}
	return serde.MarshalCBOR(dto)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (p *Point) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*pointDTO](data)
	if err != nil {
		return err
	}

	pp, err := NewCurve().FromUncompressed(dto.AffineUnompressedBytes)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

// MarshalCBOR implements cbor.Marshaler.
func (p *PrimeSubGroupPoint) MarshalCBOR() ([]byte, error) {
	dto := &pointDTO{AffineUnompressedBytes: p.ToUncompressed()}
	return serde.MarshalCBOR(dto)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (p *PrimeSubGroupPoint) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*pointDTO](data)
	if err != nil {
		return err
	}

	pp, err := NewPrimeSubGroup().FromUncompressed(dto.AffineUnompressedBytes)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}
