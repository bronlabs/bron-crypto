//go:build purego || nobignum

package numct

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

var (
	_ cbor.Marshaler   = (*ModulusOddPrimeBasic)(nil)
	_ cbor.Unmarshaler = (*ModulusOddPrimeBasic)(nil)
	_ cbor.Marshaler   = (*ModulusOddBasic)(nil)
	_ cbor.Unmarshaler = (*ModulusOddBasic)(nil)
)

func (m *ModulusOddPrimeBasic) MarshalCBOR() ([]byte, error) {
	serial := &modulusDTO{N: m.Nat()}
	return serde.MarshalCBORTagged(serial, ModulusOddPrimeBasicTag)
}

func (m *ModulusOddPrimeBasic) UnmarshalCBOR(data []byte) error {
	serial, err := serde.UnmarshalCBOR[*modulusDTO](data)
	if err != nil {
		return err
	}
	if serial.N == nil {
		return errs.NewIsNil("modulus data")
	}
	if serial.N.IsEven() == ct.True || serial.N.IsProbablyPrime() == ct.False {
		return errs.NewValue("not a valid odd prime modulus")
	}
	mod := newModulusOddPrimeBasic(serial.N)
	m.Set(mod)
	return nil
}

func (m *ModulusOddBasic) MarshalCBOR() ([]byte, error) {
	serial := &modulusDTO{N: m.Nat()}
	return serde.MarshalCBORTagged(serial, ModulusOddBasicTag)
}

func (m *ModulusOddBasic) UnmarshalCBOR(data []byte) error {
	serial, err := serde.UnmarshalCBOR[*modulusDTO](data)
	if err != nil {
		return err
	}
	if serial.N == nil {
		return errs.NewIsNil("modulus data")
	}
	if serial.N.IsEven() == ct.True {
		return errs.NewValue("not an odd modulus")
	}
	mod := newModulusOddBasic(serial.N)
	m.Set(mod)
	return nil
}
