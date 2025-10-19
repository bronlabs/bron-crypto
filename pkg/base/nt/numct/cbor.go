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
	_ cbor.Marshaler   = (*ModulusBasic)(nil)
	_ cbor.Unmarshaler = (*ModulusBasic)(nil)
)

const (
	ModulusOddPrimeTag      = 5001
	ModulusOddPrimeBasicTag = 5002
	ModulusOddTag           = 5003
	ModulusOddBasicTag      = 5004
	ModulusBasicTag         = 5005
)

func init() {
	serde.Register[*ModulusOddPrime](ModulusOddPrimeTag)
	serde.Register[*ModulusOddPrimeBasic](ModulusOddPrimeBasicTag)
	serde.Register[*ModulusOdd](ModulusOddTag)
	serde.Register[*ModulusOddBasic](ModulusOddBasicTag)
	serde.Register[*ModulusBasic](ModulusBasicTag)
}

type natDTO struct {
	NatBytes []byte `cbor:"natBytes"`
}

func (n *Nat) MarshalCBOR() ([]byte, error) {
	dto := &natDTO{NatBytes: n.Bytes()}
	return serde.MarshalCBOR(dto)
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
	IntBytes   []byte `cbor:"intBytes"`
	IsNegative bool   `cbor:"isNegative"`
}

func (i *Int) MarshalCBOR() ([]byte, error) {
	dto := &intDTO{
		IntBytes:   i.Bytes(),
		IsNegative: i.IsNegative() == ct.True,
	}
	return serde.MarshalCBOR(dto)
}

func (i *Int) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*intDTO](data)
	if err != nil {
		return err
	}
	i.SetBytes(dto.IntBytes)
	if dto.IsNegative {
		i.Neg(i)
	}
	return nil
}

type modulusDTO struct {
	N *Nat `cbor:"modulus"`
}

func (m *ModulusBasic) MarshalCBOR() ([]byte, error) {
	serial := &modulusDTO{N: m.Nat()}
	return serde.MarshalCBORTagged(serial, ModulusBasicTag)
}

func (m *ModulusBasic) UnmarshalCBOR(data []byte) error {
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
	mod := newModulusBasic(serial.N)
	m.Set(mod)
	return nil
}
