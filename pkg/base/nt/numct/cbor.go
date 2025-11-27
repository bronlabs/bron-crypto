package numct

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

var (
	_ cbor.Marshaler   = (*Nat)(nil)
	_ cbor.Unmarshaler = (*Nat)(nil)
	_ cbor.Marshaler   = (*Int)(nil)
	_ cbor.Unmarshaler = (*Int)(nil)
	_ cbor.Marshaler   = (*Modulus)(nil)
	_ cbor.Unmarshaler = (*Modulus)(nil)
)

type natDTO struct {
	NatBytes []byte `cbor:"natBytes"`
}

func (n *Nat) MarshalCBOR() ([]byte, error) {
	dto := &natDTO{NatBytes: n.Bytes()}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal Nat")
	}
	return data, nil
}

func (n *Nat) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*natDTO](data)
	if err != nil {
		return err
	}
	n.SetBytes(dto.NatBytes)
	return nil
}

type intDTO struct {
	IntBytes []byte `cbor:"intBytes"`
}

func (i *Int) MarshalCBOR() ([]byte, error) {
	dto := &intDTO{
		IntBytes: i.Bytes(),
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal Int")
	}
	return data, nil
}

func (i *Int) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*intDTO](data)
	if err != nil {
		return err
	}
	i.SetBytes(dto.IntBytes)
	return nil
}

type modulusDTO struct {
	N *Nat `cbor:"modulus"`
}

func (m *Modulus) MarshalCBOR() ([]byte, error) {
	serial := &modulusDTO{N: m.Nat()}
	data, err := serde.MarshalCBOR(serial)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal ModulusBasic")
	}
	return data, nil
}

func (m *Modulus) UnmarshalCBOR(data []byte) error {
	serial, err := serde.UnmarshalCBOR[*modulusDTO](data)
	if err != nil {
		return err
	}
	if serial.N == nil {
		return errs.NewIsNil("modulus data")
	}
	if serial.N.IsZero() == ct.True {
		return errs.NewValue("modulus cannot be zero")
	}
	ok := m.SetNat(serial.N)
	if ok == ct.False {
		return errs.NewValue("invalid modulus")
	}
	return nil
}
